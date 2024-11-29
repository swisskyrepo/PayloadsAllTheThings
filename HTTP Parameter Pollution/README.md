# HTTP Parameter Pollution

> HTTP Parameter Pollution (HPP) is a Web attack evasion technique that allows an attacker to craft a HTTP request in order to manipulate web logics or retrieve hidden information. This evasion technique is based on splitting an attack vector between multiple instances of a parameter with the same name (?param1=value&param1=value). As there is no formal way of parsing HTTP parameters, individual web technologies have their own unique way of parsing and reading URL parameters with the same name. Some taking the first occurrence, some taking the last occurrence, and some reading it as an array. This behavior is abused by the attacker in order to bypass pattern-based security mechanisms. 

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Parameter Pollution Table](#parameter-pollution-table)
    * [Parameter Pollution Payloads](#parameter-pollution-payloads)
* [References](#references)


## Tools

* **Burp Suite**: Manually modify requests to test duplicate parameters.
* **OWASP ZAP**: Intercept and manipulate HTTP parameters.


## Methodology

HTTP Parameter Pollution (HPP) is a web security vulnerability where an attacker injects multiple instances of the same HTTP parameter into a request. The server's behavior when processing duplicate parameters can vary, potentially leading to unexpected or exploitable behavior.

HPP can target two levels:

* Client-Side HPP: Exploits JavaScript code running on the client (browser).
* Server-Side HPP: Exploits how the server processes multiple parameters with the same name.


**Examples**:

```ps1
/app?debug=false&debug=true
/transfer?amount=1&amount=5000
```


### Parameter Pollution Table

When ?par1=a&par1=b

| Technology                                      | Parsing Result           | outcome (par1=) |
| ----------------------------------------------- | ------------------------ | --------------- |
| ASP.NET/IIS                                     | All occurrences          | a,b             |
| ASP/IIS                                         | All occurrences          | a,b             |
| Golang net/http - `r.URL.Query().Get("param")`  | First occurrence         | a               |
| Golang net/http - `r.URL.Query()["param"]`      | All occurrences in array | ['a','b']       |
| IBM HTTP Server                                 | First occurrence         | a               |
| IBM Lotus Domino                                | First occurrence         | a               |
| JSP,Servlet/Tomcat                              | First occurrence         | a               |
| mod_wsgi (Python)/Apache                        | First occurrence         | a               |
| Nodejs                                          | All occurrences          | a,b             |
| Perl CGI/Apache                                 | First occurrence         | a               |
| Perl CGI/Apache                                 | First occurrence         | a               |
| PHP/Apache                                      | Last occurrence          | b               |
| PHP/Zues                                        | Last occurrence          | b               |
| Python Django                                   | Last occurrence          | b               |
| Python Flask                                    | First occurrence         | a               |
| Python/Zope                                     | All occurrences in array | ['a','b']       |
| Ruby on Rails                                   | Last occurrence          | b               |


### Parameter Pollution Payloads

* Duplicate Parameters:
    ```ps1
    param=value1&param=value2
    ```

* Array Injection:
    ```ps1
    param[]=value1
    param[]=value1&param[]=value2
    param[]=value1&param=value2
    param=value1&param[]=value2
    ```

* Encoded Injection:
    ```ps1
    param=value1%26other=value2
    ```

* Nested Injection:
    ```ps1
    param[key1]=value1&param[key2]=value2
    ```

* JSON Injection:
    ```ps1
    {
        "test": "user",
        "test": "admin"
    }
    ```


## References

- [How to Detect HTTP Parameter Pollution Attacks - Acunetix - January 9, 2024](https://www.acunetix.com/blog/whitepaper-http-parameter-pollution/)
- [HTTP Parameter Pollution - Itamar Verta - December 20, 2023](https://www.imperva.com/learn/application-security/http-parameter-pollution/)
- [HTTP Parameter Pollution in 11 minutes - PwnFunction - January 28, 2019](https://www.youtube.com/watch?v=QVZBl8yxVX0&ab_channel=PwnFunction)