# Insecure Deserialization

> Serialization is the process of turning some object into a data format that can be restored later. People often serialize objects in order to save them to storage, or to send as part of communications. Deserialization is the reverse of that process -- taking data structured from some format, and rebuilding it into an object - OWASP

Check the following sub-sections, located in other files :

* [Java deserialization : ysoserial, ...](Java.md)
* [PHP (Object injection) : phpggc, ...](PHP.md)
* [Ruby : universal rce gadget, ...](Ruby.md)

## Thanks to

* [Github - ysoserial](https://github.com/frohoff/ysoserial)
* [Java-Deserialization-Cheat-Sheet - GrrrDog](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet/blob/master/README.md)
* [Understanding & practicing java deserialization exploits](https://diablohorn.com/2017/09/09/understanding-practicing-java-deserialization-exploits/)
* [How i found a 1500$ worth Deserialization vulnerability - @D0rkerDevil](https://medium.com/@D0rkerDevil/how-i-found-a-1500-worth-deserialization-vulnerability-9ce753416e0a)
* [Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities - 14 Aug 2017, Peter Stöckli](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)
* [PHP Object Injection - OWASP](https://www.owasp.org/index.php/PHP_Object_Injection)
* [PHP Object Injection - Thin Ba Shane](http://location-href.com/php-object-injection/)
* [PHP unserialize](http://php.net/manual/en/function.unserialize.php)
* [PHP Generic Gadget - ambionics security](https://www.ambionics.io/blog/php-generic-gadget-chains)
* [RUBY 2.X UNIVERSAL RCE DESERIALIZATION GADGET CHAIN - elttam, Luke Jahnke](https://www.elttam.com.au/blog/ruby-deserialization/)