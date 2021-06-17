# Chapter 3 - Invisible is Best (Operating in Memory)
This chapter is all about process injection, hiding in memory, and detecting process injection techniques

## Topics

This chapter covers several topics such as:

-   Dead disk forensics
-   The offensive shift to memory operations
-   The defensive shift to Endpoint Detection and Response (EDR) frameworks
-   Process injection with CreateRemoteThread
-   Position independent shellcode
-   The EternalBlue exploit
-   Automating Metasploit to process inject Sliver agents
-   Detecting process injection with multiple tools and techniques
-   Configuring defensive tools to alert on process injection
-   Detecting malicious activity behaviorally

## Code
The following are some of the code samples included in this chapter:

- [CreateRemoteThread.go](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter3/CreateRemoteThread.go)
	- A basic process CreateRemoteThread injection program based on [needle](https://github.com/vyrus001/needle)
- [auto_inject.rc](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter3/auto_inject.rc)
    - Metasploit automation to inject shellcode with CreateRemoteThread via a Meterpreter session 

## Images
These are some of the images in this chapter to help understand memory operations


The following image demonstrates the extra steps the defense must take and the ephemeral attributes added to offensive oppations when tools are executed in memory \ 
![disk vs memoery tradeoff](https://raw.githubusercontent.com/ahhh/Cybersecurity-Tradecraft/main/Chapter3/diskvsmemory.PNG)


The next image demonstrates the above attack tree when placed inside an offensive kill chain \
![memory ops kill chain](https://raw.githubusercontent.com/ahhh/Cybersecurity-Tradecraft/main/Chapter3/memorytradeoffkillchain.PNG)


The last image represents how the defense can prepare for these opperations to detect and respond to them sooner \
![defense ready for memory ops](https://raw.githubusercontent.com/ahhh/Cybersecurity-Tradecraft/main/Chapter3/defendermemoryaware.PNG)
