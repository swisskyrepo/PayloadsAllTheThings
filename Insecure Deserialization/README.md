# Insecure Deserialization

> Serialization is the process of turning some object into a data format that can be restored later. People often serialize objects in order to save them to storage, or to send as part of communications. Deserialization is the reverse of that process -- taking data structured from some format, and rebuilding it into an object - OWASP

## Summary

* [Deserialization Identifier](#deserialization-identifier)
* [POP Gadgets](#pop-gadgets)
* [Labs](#labs)
* [References](#references)


## Deserialization Identifier

Check the following sub-sections, located in other chapters :

* [Java deserialization : ysoserial, ...](Java.md)
* [PHP (Object injection) : phpggc, ...](PHP.md)
* [Ruby : universal rce gadget, ...](Ruby.md)
* [Python : pickle, ...](Python.md)
* [YAML : PyYAML, ...](YAML.md)
* [.NET : ysoserial.net, ...](DotNET.md)

| Object Type     | Header (Hex) | Header (Base64) |
|-----------------|--------------|-----------------|
| Java Serialized | AC ED        | rO              |
| .NET ViewState  | FF 01        | /w              |
| Python Pickle   | 80 04 95     | gASV            |
| PHP Serialized  | 4F 3A        | Tz              |


## POP Gadgets

> A POP (Property Oriented Programming) gadget is a piece of code implemented by an application's class, that can be called during the deserialization process.

POP gadgets characteristics:
* Can be serialized
* Has public/accessible properties
* Implements specific vulnerable methods
* Has access to other "callable" classes


## Labs

* [Portswigger - Insecure Deserialization](https://portswigger.net/web-security/all-labs#insecure-deserialization)
* [NickstaDB/DeserLab - Java deserialization exploitation lab](https://github.com/NickstaDB/DeserLab)


## References

- [ExploitDB Introduction - Abdelazim Mohammed(@intx0x80) - May 27, 2018](https://www.exploit-db.com/docs/english/44756-deserialization-vulnerability.pdf)
- [Exploiting insecure deserialization vulnerabilities - PortSwigger - July 25, 2020](https://portswigger.net/web-security/deserialization/exploiting)
- [Instagram's Million Dollar Bug - Wesley Wineberg - December 17, 2015](http://www.exfiltrated.com/research-Instagram-RCE.php)