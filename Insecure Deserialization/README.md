# Insecure Deserialization

> Serialization is the process of turning some object into a data format that can be restored later. People often serialize objects in order to save them to storage, or to send as part of communications. Deserialization is the reverse of that process -- taking data structured from some format, and rebuilding it into an object - OWASP

Check the following sub-sections, located in other files :

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

* [Github - frohoff/ysoserial](https://github.com/frohoff/ysoserial)
* [Github - pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)
* [Java-Deserialization-Cheat-Sheet - GrrrDog](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet/blob/master/README.md)
* [Understanding & practicing java deserialization exploits](https://diablohorn.com/2017/09/09/understanding-practicing-java-deserialization-exploits/)
* [How i found a 1500$ worth Deserialization vulnerability - @D0rkerDevil](https://medium.com/@D0rkerDevil/how-i-found-a-1500-worth-deserialization-vulnerability-9ce753416e0a)
* [Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities - 14 Aug 2017, Peter Stöckli](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)
* [PHP Object Injection - OWASP](https://www.owasp.org/index.php/PHP_Object_Injection)
* [PHP Object Injection - Thin Ba Shane](http://location-href.com/php-object-injection/)
* [PHP unserialize](http://php.net/manual/en/function.unserialize.php)
* [PHP Generic Gadget - ambionics security](https://www.ambionics.io/blog/php-generic-gadget-chains)
* [RUBY 2.X UNIVERSAL RCE DESERIALIZATION GADGET CHAIN - elttam, Luke Jahnke](https://www.elttam.com.au/blog/ruby-deserialization/)
* [Java Deserialization in manager.paypal.com](http://artsploit.blogspot.hk/2016/01/paypal-rce.html) by Michael Stepankin
* [Instagram's Million Dollar Bug](http://www.exfiltrated.com/research-Instagram-RCE.php) by Wesley Wineberg 
* [Ruby Cookie Deserialization RCE on facebooksearch.algolia.com](https://hackerone.com/reports/134321) by Michiel Prins (michiel)
* [Java deserialization](https://seanmelia.wordpress.com/2016/07/22/exploiting-java-deserialization-via-jboss/) by meals
* [Diving into unserialize() - Sep 19- Vickie Li](https://medium.com/swlh/diving-into-unserialize-3586c1ec97e)
* [.NET Gadgets](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf) by Alvaro Muñoz (@pwntester) & OleksandrMirosh
* [ExploitDB Introduction](https://www.exploit-db.com/docs/english/44756-deserialization-vulnerability.pdf)
* [Exploiting insecure deserialization vulnerabilities - PortSwigger](https://portswigger.net/web-security/deserialization/exploiting)