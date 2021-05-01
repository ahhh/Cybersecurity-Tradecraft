# Network Monitoring
The following are tools to generate more network telemetry and collection

## tcpdump
This is a quick one liner to capture network traffic on a specific interface (eth0):

`$ sudo tcpdump -i eth0 -tttt -s 0 -w outfile.pcap`

## tshark
This is a one liner that will capture all source IPs, destination IPs, and destination ports:

`$ sudo tshark -i eth0 -nn -e ip.src -e ip.dst -e tcp.dstport -Tfields -E separator=, -Y ip > outfile.txt`
