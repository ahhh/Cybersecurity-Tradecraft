# Blocking IP addresses
The following are basic rules to block IP addresses on both Linux and Windows

## Blocking on Linux
This will drop all traffic coming from a specific IP address, for example 
```
$ sudo iptables -A INPUT -s 172.31.33.7 -j DROP
```
This next command will block all traffic going to a specific IP address (in the event they have a reverse shell)
```
$ sudo iptables -A OUTPUT -s 172.31.33.7 -j DROP
```
## Blocking on Windows
We can block the same inbound traffic on Windows with:
```
> New-NetFirewallRule -DisplayName "AttackerX 1 IP In" -Direction Inbound –LocalPort Any -Protocol TCP -Action Block -RemoteAddress 172.31.33.7
```
And we can block the traffic outbound on Windows with:
```
> New-NetFirewallRule -DisplayName "AttackerX 1 IP Out" -Direction Outbound –LocalPort Any -Protocol TCP -Action Block -RemoteAddress 172.31.33.7
```
