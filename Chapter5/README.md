# Chapter 5 - Active Manipulation
This chapter is about actively tampering with the opponents tools and sensors, actively deceiving your opponents

## Topics

This chapter covers several topics such as:

-   Deleting logs 
-   Backdooring frameworks
-   Rootkits
-   Data integrity
-   Detecting rootkits
-   Manipulating the home field advantage
-   Deceiving attackers on the network
-   Tricking attackers into executing your code

## Code
The following are some of the code samples included in this chapter:

- [iptables_tricks.md](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter5/iptables_tricks.md)
	- Several iptables tricks to manipulate network traffic and deceive an attacker 
- [wrap_log.go](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter5/wrap_log.go)
    - A universal utility to replace system binaries and intercept or log their usage 

## Images
The following are some of the images in this chapter:

This image shows how an attacker could delete local logs and effect an incident response investigation
![An attacker modifies the logs in their kill chain](https://raw.githubusercontent.com/ahhh/Cybersecurity-Tradecraft/main/Chapter5/logmodification.PNG)

This image shows how a defender can use remote logging and detect when a pipeline goes down
![Defender uses remote loggign and detects when a pipeline goes down](https://raw.githubusercontent.com/ahhh/Cybersecurity-Tradecraft/main/Chapter5/remotelogging.PNG)

This last image shows what it could look like if an attacker used a rootkit
![Rootkit is deployed and detected](https://raw.githubusercontent.com/ahhh/Cybersecurity-Tradecraft/main/Chapter5/rootkitusedetected.PNG)
