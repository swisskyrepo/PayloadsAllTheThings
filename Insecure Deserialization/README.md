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

* [PortSwigger - Modifying serialized objects](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)
* [PortSwigger - Modifying serialized data types](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types)
* [PortSwigger - Using application functionality to exploit insecure deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization)
* [PortSwigger - Arbitrary object injection in PHP](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)
* [PortSwigger - Exploiting Java deserialization with Apache Commons](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons)
* [PortSwigger - Exploiting PHP deserialization with a pre-built gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain)
* [PortSwigger - Exploiting Ruby deserialization using a documented gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-ruby-deserialization-using-a-documented-gadget-chain)
* [PortSwigger - Developing a custom gadget chain for Java deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-java-deserialization)
* [PortSwigger - Developing a custom gadget chain for PHP deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization)
* [PortSwigger - Using PHAR deserialization to deploy a custom gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-phar-deserialization-to-deploy-a-custom-gadget-chain)
* [NickstaDB - DeserLab](https://github.com/NickstaDB/DeserLab)


## References

- [ExploitDB Introduction - Abdelazim Mohammed(@intx0x80) - May 27, 2018](https://www.exploit-db.com/docs/english/44756-deserialization-vulnerability.pdf)
- [Exploiting insecure deserialization vulnerabilities - PortSwigger - July 25, 2020](https://portswigger.net/web-security/deserialization/exploiting)
- [Instagram's Million Dollar Bug - Wesley Wineberg - December 17, 2015](http://www.exfiltrated.com/research-Instagram-RCE.php)