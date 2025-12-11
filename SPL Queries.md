# SPL Queries





**Verify Victim IP**

index=pcap\_analysis 

| stats count by ip\_dst 

| sort -count



**Top 10 Attackers**

index=pcap\_analysis ip\_dst="203.161.44.208"

| stats count by ip\_src 

| sort -count 

| head 10



**Analyze Port Scanning Activity**

index=pcap\_analysis ip\_dst="203.161.44.208"

| stats count by tcp\_dstport 

| sort -count 

| head 20



**Timeline of Scanning Activity**

index=pcap\_analysis ip\_dst="203.161.44.208"

| timechart count by ip\_src limit=5



**Identify Scan Types by TCP Flags**

index=pcap\_analysis ip\_dst="203.161.44.208" tcp\_flags=\*

| stats count by tcp\_flags 

| sort -count



**Protocol Distribution**

index=pcap\_analysis 

| stats count by ip\_proto 

| sort -count



**Create Summary Table**

index=pcap\_analysis ip\_dst="203.161.44.208"

| stats count as "Total Packets", 

&nbsp;       dc(ip\_src) as "Unique Scanners", 

&nbsp;       dc(tcp\_dstport) as "Unique Ports Scanned",

&nbsp;       earliest(\_time) as "First Scan",

&nbsp;       latest(\_time) as "Last Scan"

| eval "First Scan"=strftime('First Scan', "%Y-%m-%d %H:%M:%S")

| eval "Last Scan"=strftime('Last Scan', "%Y-%m-%d %H:%M:%S")



**Detection Rule**

index=pcap\_analysis 

| stats count by ip\_src, ip\_dst 

| where count > 1000

| eval alert="Potential Port Scan Detected"

| table alert, ip\_src, ip\_dst, count







**Attack Summary**

index=pcap\_analysis ip\_dst="203.161.44.208"

| stats count as "Total Packets", 

&nbsp;       dc(ip\_src) as "Unique Scanners", 

&nbsp;       dc(tcp\_dstport) as "Ports Targeted"







**📋 DASHBOARD PANEL SEARCHES** 



**Attack Summary**

index=pcap\_analysis ip\_dst="203.161.44.208"

| stats count as "Total Packets", 

&nbsp;       dc(ip\_src) as "Unique Scanners", 

&nbsp;       dc(tcp\_dstport) as "Ports Targeted"





**Top 10 Attacking IPs**

index=pcap\_analysis ip\_dst="203.161.44.208"

| stats count as "Packets" by ip\_src 

| sort -count 

| head 10





**Scanning Activity Timeline (Top 5 Attackers)**

index=pcap\_analysis ip\_dst="203.161.44.208"

| timechart span=1h count by ip\_src limit=5



**Panel 4: Most Targeted Services**

index=pcap\_analysis ip\_dst="203.161.44.208"

| stats count by tcp\_dstport 

| sort -count 

| head 15

| eval Service=case(

&nbsp;   tcp\_dstport=80, "HTTP",

&nbsp;   tcp\_dstport=443, "HTTPS",

&nbsp;   tcp\_dstport=22, "SSH",

&nbsp;   tcp\_dstport=23, "Telnet",

&nbsp;   tcp\_dstport=3389, "RDP",

&nbsp;   tcp\_dstport=445, "SMB",

&nbsp;   tcp\_dstport=1433, "MSSQL",

&nbsp;   tcp\_dstport=3306, "MySQL",

&nbsp;   tcp\_dstport=8728, "MikroTik",

&nbsp;   tcp\_dstport=6379, "Redis",

&nbsp;   1=1, "Port ".tcp\_dstport

)

| table Service, count

| sort -count





**TCP Flag Distribution (Scan Type Analysis)**

index=pcap\_analysis ip\_dst="203.161.44.208" tcp\_flags=\*

| stats count by tcp\_flags 

| eval Flag\_Type=case(

&nbsp;   tcp\_flags="0x0002", "SYN (Scan Probe)",

&nbsp;   tcp\_flags="0x0004", "RST (Port Closed)",

&nbsp;   tcp\_flags="0x0010", "ACK (Response)",

&nbsp;   tcp\_flags="0x0018", "PSH-ACK (Data)",

&nbsp;   tcp\_flags="0x0011", "FIN-ACK (Close)",

&nbsp;   1=1, "Other"

)

| stats sum(count) as Total by Flag\_Type

| sort -Total



**Attack Infrastructure Analysis**

index=pcap\_analysis ip\_dst="203.161.44.208"

| stats count as Packets by ip\_src 

| sort -Packets 

| head 10

| eval "Attack Infrastructure"=case(

&nbsp;   like(ip\_src, "79.110.%"), "Primary Scanner (79.110.62.61)",

&nbsp;   like(ip\_src, "79.124.%"), "Coordinated Botnet (79.124.62.0/24)",

&nbsp;   like(ip\_src, "104.156.%"), "Secondary Infrastructure",

&nbsp;   1=1, "Other Scanner"

)

| table ip\_src, "Attack Infrastructure", Packets

| rename ip\_src as "Source IP"



**Recent Scanning Events (Last 100)**

index=pcap\_analysis ip\_dst="203.161.44.208"

| head 100

| table \_time, ip\_src, ip\_dst, tcp\_srcport, tcp\_dstport, tcp\_flags

| rename \_time as "Time", ip\_src as "Source IP", ip\_dst as "Destination IP", tcp\_srcport as "Source Port", tcp\_dstport as "Dest Port", tcp\_flags as "TCP Flags"



**Port Scanning Heat Map Over Time**index=pcap\_analysis ip\_dst="203.161.44.208"

| bucket \_time span=1h

| stats count by \_time, tcp\_dstport

| where tcp\_dstport IN (80, 443, 22, 23, 3389, 445, 1433, 3306, 8728)



**Identify Scan Types by TCP Flags**

index=pcap\_analysis ip\_dst="203.161.44.208" tcp\_flags=\*

| stats count by tcp\_flags

| sort -count







**Protocol Distribution**

index=pcap\_analysis

| stats count by ip\_proto 

| sort -count





**Create Summary Table**

index=pcap\_analysis ip\_dst="203.161.44.208"

| stats count as "Total Packets", 

&nbsp;       dc(ip\_src) as "Unique Scanners", 

&nbsp;       dc(tcp\_dstport) as "Unique Ports Scanned",

&nbsp;       earliest(\_time) as "First Scan",

&nbsp;       latest(\_time) as "Last Scan"

| eval "First Scan"=strftime('First Scan', "%Y-%m-%d %H:%M:%S")

| eval "Last Scan"=strftime('Last Scan', "%Y-%m-%d %H:%M:%S")





**---**



**### \*\*Detection Rule - Port Scan Alert\*\***

index=pcap\_analysis 

| stats count by ip\_src, ip\_dst 

| where count > 1000

| eval alert="Potential Port Scan Detected"

| table alert, ip\_src, ip\_dst, count





**Alerts**



**High-Volume Port Scanning**

index=pcap\_analysis 

| bucket \_time span=5m 

| stats dc(tcp\_dstport) as unique\_ports, count as total\_packets by \_time, ip\_src, ip\_dst 

| where unique\_ports > 10 AND total\_packets > 50

| eval alert\_severity="HIGH"

| eval alert\_message="Port scan detected: ".ip\_src." scanned ".unique\_ports." ports on ".ip\_dst." (".total\_packets." packets in 5 min)"

| table \_time, ip\_src, ip\_dst, unique\_ports, total\_packets, alert\_severity, alert\_message





**Coordinated Botnet Scanning**

index=pcap\_analysis 

| eval source\_subnet=replace(ip\_src, "(\\d+\\.\\d+\\.\\d+)\\.\\d+", "\\1.0/24")

| bucket \_time span=10m

| stats dc(ip\_src) as unique\_scanners, dc(tcp\_dstport) as ports\_scanned, count as total\_packets by \_time, source\_subnet, ip\_dst

| where unique\_scanners >= 3 AND ports\_scanned > 5

| eval alert\_severity="CRITICAL"

| eval alert\_message="Coordinated botnet scan: ".unique\_scanners." IPs from ".source\_subnet." scanning ".ip\_dst

| table \_time, source\_subnet, ip\_dst, unique\_scanners, ports\_scanned, total\_packets, alert\_severity, alert\_message





**Critical Service Targeting**

index=pcap\_analysis 

| eval critical\_service=case(

&nbsp;   tcp\_dstport=22, "SSH",

&nbsp;   tcp\_dstport=23, "Telnet",

&nbsp;   tcp\_dstport=3389, "RDP",

&nbsp;   tcp\_dstport=445, "SMB",

&nbsp;   tcp\_dstport=1433, "MSSQL",

&nbsp;   tcp\_dstport=3306, "MySQL",

&nbsp;   tcp\_dstport=5432, "PostgreSQL",

&nbsp;   tcp\_dstport=8728, "MikroTik RouterOS",

&nbsp;   tcp\_dstport=27017, "MongoDB",

&nbsp;   1=1, null()

)

| where isnotnull(critical\_service)

| bucket \_time span=15m

| stats count as attempts by \_time, ip\_src, ip\_dst, tcp\_dstport, critical\_service

| where attempts > 5

| eval alert\_severity=case(

&nbsp;   tcp\_dstport=3389, "HIGH",

&nbsp;   tcp\_dstport=22, "HIGH",

&nbsp;   tcp\_dstport=8728, "CRITICAL",

&nbsp;   1=1, "MEDIUM"

)

| eval alert\_message="Critical service scan: ".ip\_src." probing ".critical\_service." (port ".tcp\_dstport.") on ".ip\_dst." - ".attempts." attempts"

| table \_time, ip\_src, ip\_dst, critical\_service, tcp\_dstport, attempts, alert\_severity, alert\_message





**SYN Flood / Reconnaissance Detection**

index=pcap\_analysis tcp\_flags=\*

| bucket \_time span=5m

| stats 

&nbsp;   count(eval(tcp\_flags="0x0002")) as syn\_count,

&nbsp;   count(eval(tcp\_flags="0x0010")) as ack\_count,

&nbsp;   count as total\_packets 

&nbsp;   by \_time, ip\_src, ip\_dst

| eval syn\_ack\_ratio=round(syn\_count/ack\_count, 2)

| where syn\_count > 100 AND syn\_ack\_ratio > 5

| eval attack\_type=case(

&nbsp;   syn\_count > 1000, "Possible SYN Flood DDoS",

&nbsp;   syn\_ack\_ratio > 10, "Stealth SYN Scan",

&nbsp;   1=1, "Reconnaissance Activity"

)

| eval alert\_severity=case(

&nbsp;   syn\_count > 1000, "CRITICAL",

&nbsp;   1=1, "HIGH"

)

| eval alert\_message=attack\_type.": ".ip\_src." sent ".syn\_count." SYN packets to ".ip\_dst." (SYN:ACK ratio ".syn\_ack\_ratio.":1)"

| table \_time, ip\_src, ip\_dst, syn\_count, ack\_count, syn\_ack\_ratio, attack\_type, alert\_severity, alert\_message





**Off-Hours Anomalous Activity**

index=pcap\_analysis 

| eval hour=tonumber(strftime(\_time, "%H"))

| eval day\_of\_week=strftime(\_time, "%A")

| where (hour >= 22 OR hour <= 6) OR day\_of\_week IN ("Saturday", "Sunday")

| bucket \_time span=1h

| stats count as packets, dc(ip\_src) as unique\_sources, dc(tcp\_dstport) as ports\_scanned by \_time, ip\_dst

| where packets > 500 OR unique\_sources > 10

| eval alert\_severity="MEDIUM"

| eval time\_period=strftime(\_time, "%Y-%m-%d %H:00")

| eval alert\_message="Off-hours scanning detected at ".time\_period.": ".packets." packets from ".unique\_sources." sources targeting ".ip\_dst

| table \_time, time\_period, ip\_dst, packets, unique\_sources, ports\_scanned, alert\_severity, alert\_message













**\*\*🚨 ALL 5 DETECTION RULES - COPY/PASTE FORMAT\*\***



**---**



**## \*\*DETECTION RULE #1: High-Volume Port Scanning\*\***



**```spl**

**index=pcap\_analysis** 

**| bucket \_time span=5m** 

**| stats dc(tcp\_dstport) as unique\_ports, count as total\_packets by \_time, ip\_src, ip\_dst** 

**| where unique\_ports > 10 AND total\_packets > 50**

**| eval alert\_severity="HIGH"**

**| eval alert\_message="Port scan detected: ".ip\_src." scanned ".unique\_ports." ports on ".ip\_dst." (".total\_packets." packets in 5 min)"**

**| table \_time, ip\_src, ip\_dst, unique\_ports, total\_packets, alert\_severity, alert\_message**

**```**



**---**



**## \*\*DETECTION RULE #2: Coordinated Botnet Scanning\*\***



**```spl**

**index=pcap\_analysis** 

**| eval source\_subnet=replace(ip\_src, "(\\d+\\.\\d+\\.\\d+)\\.\\d+", "\\1.0/24")**

**| bucket \_time span=10m**

**| stats dc(ip\_src) as unique\_scanners, dc(tcp\_dstport) as ports\_scanned, count as total\_packets by \_time, source\_subnet, ip\_dst**

**| where unique\_scanners >= 3 AND ports\_scanned > 5**

**| eval alert\_severity="CRITICAL"**

**| eval alert\_message="Coordinated botnet scan: ".unique\_scanners." IPs from ".source\_subnet." scanning ".ip\_dst**

**| table \_time, source\_subnet, ip\_dst, unique\_scanners, ports\_scanned, total\_packets, alert\_severity, alert\_message**

**```**



**---**



**## \*\*DETECTION RULE #3: Critical Service Targeting\*\***



**```spl**

**index=pcap\_analysis** 

**| eval critical\_service=case(**

    **tcp\_dstport=22, "SSH",**

    **tcp\_dstport=23, "Telnet",**

    **tcp\_dstport=3389, "RDP",**

    **tcp\_dstport=445, "SMB",**

    **tcp\_dstport=1433, "MSSQL",**

    **tcp\_dstport=3306, "MySQL",**

    **tcp\_dstport=5432, "PostgreSQL",**

    **tcp\_dstport=8728, "MikroTik RouterOS",**

    **tcp\_dstport=27017, "MongoDB",**

    **1=1, null()**

**)**

**| where isnotnull(critical\_service)**

**| bucket \_time span=15m**

**| stats count as attempts by \_time, ip\_src, ip\_dst, tcp\_dstport, critical\_service**

**| where attempts > 5**

**| eval alert\_severity=case(**

    **tcp\_dstport=3389, "HIGH",**

    **tcp\_dstport=22, "HIGH",**

    **tcp\_dstport=8728, "CRITICAL",**

    **1=1, "MEDIUM"**

**)**

**| eval alert\_message="Critical service scan: ".ip\_src." probing ".critical\_service." (port ".tcp\_dstport.") on ".ip\_dst." - ".attempts." attempts"**

**| table \_time, ip\_src, ip\_dst, critical\_service, tcp\_dstport, attempts, alert\_severity, alert\_message**

**```**



**---**



**## \*\*DETECTION RULE #4: SYN Flood / Reconnaissance Detection\*\***



**```spl**

**index=pcap\_analysis tcp\_flags=\***

**| bucket \_time span=5m**

**| stats** 

    **count(eval(tcp\_flags="0x0002")) as syn\_count,**

    **count(eval(tcp\_flags="0x0010")) as ack\_count,**

    **count as total\_packets** 

    **by \_time, ip\_src, ip\_dst**

**| eval syn\_ack\_ratio=round(syn\_count/ack\_count, 2)**

**| where syn\_count > 100 AND syn\_ack\_ratio > 5**

**| eval attack\_type=case(**

    **syn\_count > 1000, "Possible SYN Flood DDoS",**

    **syn\_ack\_ratio > 10, "Stealth SYN Scan",**

    **1=1, "Reconnaissance Activity"**

**)**

**| eval alert\_severity=case(**

    **syn\_count > 1000, "CRITICAL",**

    **1=1, "HIGH"**

**)**

**| eval alert\_message=attack\_type.": ".ip\_src." sent ".syn\_count." SYN packets to ".ip\_dst." (SYN:ACK ratio ".syn\_ack\_ratio.":1)"**

**| table \_time, ip\_src, ip\_dst, syn\_count, ack\_count, syn\_ack\_ratio, attack\_type, alert\_severity, alert\_message**

**```**



**---**



**## \*\*DETECTION RULE #5: Off-Hours Anomalous Activity\*\***



**```spl**

**index=pcap\_analysis** 

**| eval hour=tonumber(strftime(\_time, "%H"))**

**| eval day\_of\_week=strftime(\_time, "%A")**

**| where (hour >= 22 OR hour <= 6) OR day\_of\_week IN ("Saturday", "Sunday")**

**| bucket \_time span=1h**

**| stats count as packets, dc(ip\_src) as unique\_sources, dc(tcp\_dstport) as ports\_scanned by \_time, ip\_dst**

**| where packets > 500 OR unique\_sources > 10**

**| eval alert\_severity="MEDIUM"**

**| eval time\_period=strftime(\_time, "%Y-%m-%d %H:00")**

**| eval alert\_message="Off-hours scanning detected at ".time\_period.": ".packets." packets from ".unique\_sources." sources targeting ".ip\_dst**

**| table \_time, time\_period, ip\_dst, packets, unique\_sources, ports\_scanned, alert\_severity, alert\_message**





