# MigleEarator
 
 
 MigleEarator is a proof of concept for Thread Hijacking in syscalls using SysWhispers2 and some sandbox evasion tricks to further evade detection.
 
 
## Why?
 The usage of syscalls helps evading userland hooks put in place.
 
 This injection technique hijacks a currently running thread and not creating a new one, it does not trigger the PsSetCreateThreadNotifyRoutine and PsSetCreateProcessNotifyRoutine kernel callbacks.
 
 Provided a simple calculator shellcode for your testing purposes.
 
 
 
 **Please note** as the RIP is being violently changed, the program will crash once the shellcode has finished execution, unless the original thread context is resumed in an awesome manner ;)
 
 


## References
Heavily adapted code from these projects:
- https://github.com/jthuraisamy/SysWhispers2
- https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking
- https://0xpat.github.io/Malware_development_part_2/
- https://github.com/matantamir/Xorush
