# Chapter 6 - Real-Time Conflict
This chapter is about gaining the advantage when two operators are actively on the same machine

## Topics

This chapter covers several topics such as:

-   Situational system awareness
-   Clearing bash history
-   Abusing Docker
-   Keylogging
-   Screenshots
-   Getting passwords
-   Searching for secrets
-   Backdooring password utilities
-   Hijacking lateral movement channels
-   Triaging a system
-   Performing root cause analysis
-   Killing processes
-   Blocking IP addresses
-   Network quarantine
-   Rotating credentials
-   Restricting permissions
-   Hacking back

## Code
The following are some of the code samples included in this chapter:

- [histfile.md](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter6/histfile.md)
    - Tampering with the bash history file in Linux
- [fake_sudo.sh](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter6/fake_sudo.sh)
    - A bash function to steal passwords when sudo is called
- [linux-pam-backdoor](https://github.com/ahhh/Cybersecurity-Tradecraft/tree/main/Chapter6/linux-pam-backdoor)
	- A Linux PAM backdoor that records credentials to a log 
- [changing_passwords.md](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter6/changing_passwords.md)
    - A set of commands to change passwords across Linux and Windows machines. The Windows examples leverage the Invoke-PasswordRoll PowerShell script 
- [Invoke-PasswordRoll.ps1](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter6/Invoke-PasswordRoll.ps1)
    - A PowerShell script to change all local account passwords on the system 
- [ip_blocking.md](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter6/ip_blocking.md)
    - Several commands to block IP addresses on both Linux and Windows
- [network_quarantine.sh](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter6/network_quarantine.sh)
    - A script to fully quarantine a Linux host, allowing only traffic from an administrative IP
