# Chapter 4 - Blending In
This chapter is about the tradeoff between in-memory operations and blending into normal activity

## Topics

This chapter covers several topics such as:

-   LOLbins
-   DLL search order hijacking
-   Executable file infection
-   Covert command and control (C2) channels
-   ICMP C2
-   DNS C2
-   Domain fronting
-   Combining offensive techniques
-   Detecting ICMP C2
-   Detecting DNS C2
-   Windows centralized DNS
-   DNS insight with Sysmon
-   Network monitoring
-   DNS analysis
-   Detecting DLL search order hijacking
-   Detecting backdoored executables
-   Honey tokens
-   Honeypots

## Code
The following are some of the code samples included in this chapter:

- [windows_LOLbins.md](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter4/windows_LOLbins.md)
	- Some examples of Windows Living Off the Land binaries
- [windows_SysmonLogs.md](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter4/windows_SysmonLogs.md)
    - Some automation around retrieving and parsing Sysmon and Windows Event Logs 


## Images
The following are some of the images included in this chapter:

This image shows some of the considerations the offense may make before choosing a cover communication channel for their opperations
![Offensive C2 planning considerations](https://raw.githubusercontent.com/ahhh/Cybersecurity-Tradecraft/main/Chapter4/c2planning.PNG)

This image shows how domain fronting will abuse a CDN to hide malicious traffic
![Offensive CND use in domain fronting](https://raw.githubusercontent.com/ahhh/Cybersecurity-Tradecraft/main/Chapter4/domainfronting.PNG)

This image shows how an attacker can use multiple covert channels in their kill chain
![Multiple covert channels in a kill chain](https://raw.githubusercontent.com/ahhh/Cybersecurity-Tradecraft/main/Chapter4/killchainc2.PNG)

This last image shows what it looks like when a defender is aware of these channels and activly monitors them
![Defender logs and analyzes DNS records](https://raw.githubusercontent.com/ahhh/Cybersecurity-Tradecraft/main/Chapter4/defenderlogsdns.PNG)
