# Dropping traffic based on TTL
The following are some tricks to drop traffic based on the TTL, or network hops
## Drop remote Linux
These rules will drop any traffic with a TTL less than 63. The default TTL for most Linux systems is 64, meaning these will drop default Linux traffic not on the same local network:
```
$ sudo iptables -A INPUT -m ttl --ttl-lt 63 -j DROP
$ sudo iptables -A OUTPUT -m ttl --ttl-lt 63 -j DROP
```
These next rules will drop any traffic with a TTL larger than 65, targeting Windows machines that have a default TTL of 128::
```
$ sudo iptables -A INPUT -m ttl --ttl-gt 65 -j DROP
$ sudo iptables -A OUTPUT -m ttl --ttl-gt 65 -j DROP
```
