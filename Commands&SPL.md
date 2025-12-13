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



## Detection Rules

# High-Volume Port Scanning

# Coordinated Botnet Scanning

# Critical Service Targeting

# SYN Flood Detection

# Off-Hours Activity
