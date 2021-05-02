#!/bin/sh 
# Run as root
# Admin and server ip addresses 
ADMIN_IP="X" 
SERVER_IP="Y" 
# Flushing all rules 
iptables -F 
iptables -X 
# Add our admin whitelist rule 
iptables -A INPUT -s $ADMIN_IP -j ACCEPT 
iptables -A OUTPUT -d $ADMIN_IP -j ACCEPT 
# Setting default filter policy 
iptables -P INPUT DROP 
iptables -P OUTPUT DROP 
iptables -P FORWARD DROP 
# Allow traffic on loopback 
iptables -A INPUT -i lo -j ACCEPT 
iptables -A OUTPUT -o lo -j ACCEPT 
# Only allow admin to SSH 
iptables -A INPUT -p tcp -s $ADMIN_IP -d $SERVER_IP --sport 513:65535 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT 
iptables -A OUTPUT -p tcp -s $SERVER_IP -d $ADMIN_IP --sport 22 --dport 513:65535 -m state --state ESTABLISHED -j ACCEPT 
# Drop everything else and save 
iptables -A INPUT -j DROP 
iptables -A OUTPUT -j DROP 
iptables-save 
