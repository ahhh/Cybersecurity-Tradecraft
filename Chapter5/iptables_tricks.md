# Tricks with iptables
The following are some techniques with iptables to mess with an attacker's network traffic or scans

## Dropping traffic

This will randomly drop 70% of the traffic inbound over SSH:
```
$ sudo iptables -A INPUT -m statistic --mode random --probability 0.7 -s 0/0 -d 0/0 -p tcp --dport 22 -j DROP
```
This next command will randomly drop 70% of the outbound traffic over port 9999
```
$ sudo iptables -A OUTPUT -m statistic --mode random --probability 0.7 -s 0/0 -d 0/0 -p tcp --dport 9999 -j DROP
```
## Spoofing ports
This command will redirect every port, except 22 and 80, to local port 4444 (where you can run a tool like [portspoof](https://github.com/drk1wi/portspoof)):
```
$ sudo iptables -t nat -A PREROUTING -i eth0 -p tcp -m tcp -m multiport --dports 1:21,23:52,54:79,81:65535 -j REDIRECT --to-ports 4444
```
## Tarpitting traffic
This next command uses the [Xtables_addons](https://inai.de/projects/xtables-addons/) for iptables to set the TCP window size to 0 for port 3306, but keep the connection open, classily known as a network tarpit
```
$ sudo iptables -A INPUT -p tcp --dport 3306 -j TARPIT
```
This last command will clear all of the iptables rules:
```
$ sudo iptables -F
```
