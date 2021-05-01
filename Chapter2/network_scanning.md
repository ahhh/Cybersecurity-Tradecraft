# Network Scanning
The following are some optimized network scanning configurations for faster scanning

## turbonmap

This is an alias for a fine-tuned nmap configuration:
```
$ alias turbonmap=‘nmap -sS -Pn --host-timeout=1m --max-rtt-timeout=600ms --initial-rtt-timeout=300ms --min-rtt-timeout=300ms --stats-every 10s --top-ports 500 --min-rate 1000 --max-retries 0 -n -T5 --min-hostgroup 255 -oA fast_scan_output -iL’
$ turbonmap 192.168.0.1/24
```
## masscan to nmap
This will use masscan to determine live hosts, then perform a deeper scan on those hosts with nmap
```
$ sudo masscan 192.168.0.1/24 -oG initial.gnmap -p 7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157 --rate 10000
$ egrep '^Host: ' initial.gnmap | cut -d" " -f2 | sort | uniq > alive.hosts
$ nmap -Pn -n -T4 --host-timeout=5m --max-retries 0 -sV -iL alive.hosts -oA nmap-version-scan
```
