# Server Side Template Injection

> Template injection allows an attacker to include template code into an existing (or not) template. A template engine makes designing HTML pages easier by using static template files which at runtime replaces variables/placeholders with actual values in the HTML pages

## Summary

- [Tools](#tools)
- [Methodology](#methodology)
- [References](#references)


## Tools

* [Hackmanit/TInjA](https://github.com/Hackmanit/TInjA) - An effiecient SSTI + CSTI scanner which utilizes novel polyglots
  ```bash
  tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
  tinja url -u "http://example.com/" -d "username=Kirlia"  -c "PHPSESSID=ABC123..."
  ```

* [epinna/tplmap](https://github.com/epinna/tplmap) - Server-Side Template Injection and Code Injection Detection and Exploitation Tool
  ```powershell
  python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
  ```

* [vladko312/SSTImap](https://github.com/vladko312/SSTImap) - Automatic SSTI detection tool with interactive interface based on [epinna/tplmap](https://github.com/epinna/tplmap)
  ```powershell
  python3 ./sstimap.py -u 'https://example.com/page?name=John' -s
  python3 ./sstimap.py -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e jade
  python3 ./sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
  ```


## Methodology

### Identify the Vulnerable Input Field

The attacker first locates an input field, URL parameter, or any user-controllable part of the application that is passed into a server-side template without proper sanitization or escaping. 

For example, the attacker might identify a web form, search bar, or template preview functionality that seems to return results based on dynamic user input.

**TIP**: Generated PDF files, invoices and emails usually use a template. 


### Inject Template Syntax

The attacker tests the identified input field by injecting template syntax specific to the template engine in use. Different web frameworks use different template engines (e.g., Jinja2 for Python, Twig for PHP, or FreeMarker for Java). 

Common template expressions:

* `{{7*7}}` for Jinja2 (Python).
* `#{7*7}` for Thymeleaf (Java).

Find more template expressions in the page dedicated to the technology (PHP, Python, etc).

![SSTI cheatsheet workflow](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/serverside.png?raw=true)

In most cases, this polyglot payload will trigger an error in presence of a SSTI vulnerability:

```ps1
${{<%[%'"}}%\.
```

The [Hackmanit/Template Injection Table](https://github.com/Hackmanit/template-injection-table) is an interactive table containing the most efficient template injection polyglots along with the expected responses of the 44 most important template engines.


### Enumerate the Template Engine

Based on the successful response, the attacker determines which template engine is being used. This step is critical because different template engines have different syntax, features, and potential for exploitation. The attacker may try different payloads to see which one executes, thereby identifying the engine.

* **Python**: Django, Jinja2, Mako, ...
* **Java**: Freemarker, Jinjava, Velocity, ...
* **Ruby**: ERB, Slim, ...

[The post "template-engines-injection-101" from @0xAwali](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756) summarize the syntax and detection method for most of the template engines for JavaScript, Python, Ruby, Java and PHP and how to differentiate between engines that use the same syntax.


### Escalate to Code Execution

Once the template engine is identified, the attacker injects more complex expressions, aiming to execute server-side commands or arbitrary code. 


## References

* [https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
* [Ruby ERB Template injection - TrustedSec](https://www.trustedsec.com/2017/09/rubyerb-template-injection/)
* [Gist - Server-Side Template Injection - RCE For the Modern WebApp by James Kettle (PortSwigger)](https://gist.github.com/Yas3r/7006ec36ffb987cbfb98)
* [PDF - Server-Side Template Injection: RCE for the modern webapp - @albinowax](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
* [VelocityServlet Expression Language injection](https://magicbluech.github.io/2017/11/15/VelocityServlet-Expression-language-Injection/)
* [Cheatsheet - Flask & Jinja2 SSTI - Sep 3, 2018 • By phosphore](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)
* [RCE in Hubspot with EL injection in HubL - @fyoorer](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html?spref=tw)
* [Jinja2 template injection filter bypasses - @gehaxelt, @0daywork](https://0day.work/jinja2-template-injection-filter-bypasses/)
* [Gaining Shell using Server Side Template Injection (SSTI) - David Valles - Aug 22, 2018](https://medium.com/@david.valles/gaining-shell-using-server-side-template-injection-ssti-81e29bb8e0f9)
* [EXPLOITING SERVER SIDE TEMPLATE INJECTION WITH TPLMAP - BY: DIVINE SELORM TSA - 18 AUG 2018](https://www.owasp.org/images/7/7e/Owasp_SSTI_final.pdf)
* [Server Side Template Injection – on the example of Pebble - MICHAŁ BENTKOWSKI | September 17, 2019](https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/)
* [Server-Side Template Injection (SSTI) in ASP.NET Razor - Clément Notin - 15 APR 2020](https://clement.notin.org/blog/2020/04/15/Server-Side-Template-Injection-(SSTI)-in-ASP.NET-Razor/)
* [Expression Language injection - PortSwigger](https://portswigger.net/kb/issues/00100f20_expression-language-injection)
* [Bean Stalking: Growing Java beans into RCE - July 7, 2020 - Github Security Lab](https://securitylab.github.com/research/bean-validation-RCE)
* [Remote Code Execution with EL Injection Vulnerabilities - Asif Durani - 29/01/2019](https://www.exploit-db.com/docs/english/46303-remote-code-execution-with-el-injection-vulnerabilities.pdf)
* [Handlebars template injection and RCE in a Shopify app ](https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html)
* [Lab: Server-side template injection in an unknown language with a documented exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)
* [Exploiting Less.js to Achieve RCE](https://www.softwaresecured.com/exploiting-less-js/)
* [A Pentester's Guide to Server Side Template Injection (SSTI)](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)
* [Django Templates Server-Side Template Injection](https://lifars.com/wp-content/uploads/2021/06/Django-Templates-Server-Side-Template-Injection-v1.0.pdf)
* [#HITB2022SIN #LAB Template Injection On Hardened Targets - Lucas 'BitK' Philippe](https://youtu.be/M0b_KA0OMFw)
* [Bug Writeup: RCE via SSTI on Spring Boot Error Page with Akamai WAF Bypass - Dec 4, 2022](https://h1pmnh.github.io/post/writeup_spring_el_waf_bypass/)
* [Leveraging the Spring Expression Language (SpEL) injection vulnerability ( a.k.a The Magic SpEL) to get RCE - Xenofon Vassilakopoulos - November 18, 2021](https://xen0vas.github.io/Leveraging-the-SpEL-Injection-Vulnerability-to-get-RCE/)
* [Expression Language Injection - OWASP](https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection)
* [Template Engines Injection 101 - Mahmoud M. Awali - Nov 1, 2024](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)