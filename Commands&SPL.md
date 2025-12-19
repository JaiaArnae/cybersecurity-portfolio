Commands and SPL Queries

## Powershell
cd /path/to/the/pcap

& "C:\Program Files\Wireshark\tshark.exe" -r "2024-08-30-approximately-11-days-of-server-scans-and-probes.pcap" -c 80000 -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e tcp.flags -e dns.qry.name -e http.host -e http.request.uri -e ip.proto -E header=y -E separator=, -E quote=d -E occurrence=f | Out-File -FilePath "traffic_analysis.csv" -Encoding UTF8
Note: SPlink does not like ".", replace them with "_"

## Add as data in Splunk

source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv"

## Check Field Names
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv"
| head 1
| transpose

# SPL Queries for Analysis


## Verify Victim IP
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv"
| stats count by ip_dst 
| sort -count

**Dashboard - Statistic Table**
source="83024ServerScan.csv" index="83024serverscan" ip_dst="203.161.44.208"
| stats count as "Total Packets", 
        dc(ip_src) as "Unique Attackers", 
        dc(tcp_dstport) as "Ports Targeted"


## Top 10 Attackers
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv" ip_dst="203.161.44.208"
| stats count by tcp_dstport 
| sort -count 
| head 20

**Dashboard - Table**
source="83024ServerScan.csv" index="83024serverscan" ip_dst="203.161.44.208"
| stats count as Packets by ip_src 
| sort -Packets
| head 10
| rename ip_src as "Attacker IP"


## Analyze Port Scanning Activity
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv" ip_dst="203.161.44.208"
| timechart count by ip_src limit=5

**Dashboard - Line Chart**
source="83024ServerScan.csv" index="83024serverscan" ip_dst="203.161.44.208"
| timechart span=1h count by ip_src limit=5


## Timeline of Scanning Activity
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv" ip_dst="203.161.44.208" tcp_flags=*
| stats count by tcp_flags 
| sort -count

**Dashboard - Bar Chart**
source="83024ServerScan.csv" index="83024serverscan" ip_dst="203.161.44.208"
| stats count by tcp_dstport 
| sort -count 
| head 15
| eval Service=case(
    tcp_dstport=80, "HTTP",
    tcp_dstport=443, "HTTPS",
    tcp_dstport=22, "SSH",
    tcp_dstport=23, "Telnet",
    tcp_dstport=3389, "RDP",
    tcp_dstport=445, "SMB",
    tcp_dstport=1433, "MSSQL",
    tcp_dstport=3306, "MySQL",
    tcp_dstport=8728, "MikroTik",
    1=1, "Port ".tcp_dstport
)
| stats sum(count) as Total by Service
| sort -Total

## TCP Flags Analysis
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv" ip_dst="203.161.44.208" tcp_flags=*
| stats count by tcp_flags 
| sort -count

**Dashboard - Pie Chart**
source="83024ServerScan.csv" index="83024serverscan" ip_dst="203.161.44.208" tcp_flags=*
| stats count by tcp_flags 
| eval Scan_Type=case(
    tcp_flags="0x0002", "SYN Scan",
    tcp_flags="0x0004", "RST (Closed)",
    tcp_flags="0x0010", "ACK",
    tcp_flags="0x0014", "ACK Response",
    tcp_flags="0x0018", "PSH-ACK",
    1=1, "Other"
)
| stats sum(count) as Total by Scan_Type
| sort -Total


## Protocol Distribution
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv"
| stats count by ip_proto 
| sort -count

**Dashboard - Pie Chart**
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv"
| stats count by ip_proto 
| eval Protocol=case(
    ip_proto=6, "TCP",
    ip_proto=17, "UDP",
    ip_proto=1, "ICMP",
    1=1, "Other ("+ip_proto+")"
)
| stats sum(count) as Total by Protocol
| sort -Total


## Summary Table & Dashboard SPL
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv" ip_dst="203.161.44.208"
| stats count as "Total Packets", 
        dc(ip_src) as "Unique Scanners", 
        dc(tcp_dstport) as "Unique Ports Scanned",
        earliest(_time) as "First Scan",
        latest(_time) as "Last Scan"
| eval "First Scan"=strftime('First Scan', "%Y-%m-%d %H:%M:%S")
| eval "Last Scan"=strftime('Last Scan', "%Y-%m-%d %H:%M:%S")



# Detection Rules

## High-Volume Port Scanning
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv"  | bucket _time span=5m | stats dc(tcp_dstport) as unique_ports, count as total_packets by _time, ip_src, ip_dst | where unique_ports > 10 AND total_packets > 50| eval alert_severity="HIGH"| eval alert_message="Port scan detected: ".ip_src." scanned ".unique_ports." ports on ".ip_dst." (".total_packets." packets in 5 min)"| table _time, ip_src, ip_dst, unique_ports, total_packets, alert_severity, alert_message


## Coordinated Botnet Scanning
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv"
| eval source_subnet=replace(ip_src, "(\d+\.\d+\.\d+)\.\d+", "\1.0/24")
| bucket _time span=10m
| stats dc(ip_src) as unique_scanners, dc(tcp_dstport) as ports_scanned, count as total_packets by _time, source_subnet, ip_dst
| where unique_scanners >= 3 AND ports_scanned > 5
| eval alert_severity="CRITICAL"
| eval alert_message="Coordinated botnet scan: ".unique_scanners." IPs from ".source_subnet." scanning ".ip_dst
| table _time, source_subnet, ip_dst, unique_scanners, ports_scanned, total_packets, alert_severity, alert_message


## Critical Service Targeting
source="83024ServerScan.csv" index="83024serverscan" sourcetype="csv"
| eval critical_service=case(
    tcp_dstport=22, "SSH",
    tcp_dstport=23, "Telnet",
    tcp_dstport=3389, "RDP",
    tcp_dstport=445, "SMB",
    tcp_dstport=1433, "MSSQL",
    tcp_dstport=3306, "MySQL",
    tcp_dstport=5432, "PostgreSQL",
    tcp_dstport=8728, "MikroTik RouterOS",
    tcp_dstport=27017, "MongoDB",
    1=1, null()
)
| where isnotnull(critical_service)
| bucket _time span=15m
| stats count as attempts by _time, ip_src, ip_dst, tcp_dstport, critical_service
| where attempts > 5
| eval alert_severity=case(
    tcp_dstport=3389, "HIGH",
    tcp_dstport=22, "HIGH",
    tcp_dstport=8728, "CRITICAL",
    1=1, "MEDIUM"
)
| eval alert_message="Critical service scan: ".ip_src." probing ".critical_service." (port ".tcp_dstport.") on ".ip_dst." - ".attempts." attempts"
| table _time, ip_src, ip_dst, critical_service, tcp_dstport, attempts, alert_severity, alert_message



