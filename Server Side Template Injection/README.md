# Server Side Template Injection

> Template injection allows an attacker to include template code into an existing (or not) template. A template engine makes designing HTML pages easier by using static template files which at runtime replaces variables/placeholders with actual values in the HTML pages.

## Summary

- [Tools](#tools)
- [Methodology](#methodology)
    - [Detection and Exploitation Techniques](#detection-and-exploitation-techniques)
        - [Rendered](#rendered)
        - [Error-Based](#error-based)
        - [Boolean-Based](#boolean-based)
        - [Time-Based](#time-based)
        - [Out of Bounds](#out-of-bounds)
        - [Polyglot-Based](#polyglot-based)
    - [Universal Detection Payloads](#universal-detection-payloads)
    - [Manual Detection and Exploitation](#manual-detection-and-exploitation)
        - [Identify the Vulnerable Input Field](#identify-the-vulnerable-input-field)
        - [Inject Template Syntax](#inject-template-syntax)
        - [Enumerate the Template Engine](#enumerate-the-template-engine)
        - [Escalate to Code Execution](#escalate-to-code-execution)
- [Labs](#labs)
- [References](#references)

## Tools

- [Hackmanit/TInjA](https://github.com/Hackmanit/TInjA) - An efficient SSTI + CSTI scanner which utilizes novel polyglots

  ```bash
  tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
  tinja url -u "http://example.com/" -d "username=Kirlia"  -c "PHPSESSID=ABC123..."
  ```

- [epinna/tplmap](https://github.com/epinna/tplmap) - Server-Side Template Injection and Code Injection Detection and Exploitation Tool

  ```powershell
  python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
  ```

- [vladko312/SSTImap](https://github.com/vladko312/SSTImap) - Automatic SSTI detection tool with interactive interface based on [epinna/tplmap](https://github.com/epinna/tplmap)

  ```bash
  python3 ./sstimap.py -u 'https://example.com/page?name=John' -s
  python3 ./sstimap.py -i -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e jade
  python3 ./sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
  ```

## Methodology

### Detection and Exploitation Techniques

Original research:

- Rendered, Time-Based: [Server-Side Template Injection: RCE For The Modern Web App - James Kettle - August 05, 2015](https://portswigger.net/knowledgebase/papers/serversidetemplateinjection.pdf)
- Polyglot-Based: [Improving the Detection and Identification of Template Engines for Large-Scale Template Injection Scanning - Maximilian Hildebrand - September 19, 2023](https://www.hackmanit.de/images/download/thesis/Improving-the-Detection-and-Identification-of-Template-Engines-for-Large-Scale-Template-Injection-Scanning-Maximilian-Hildebrand-Master-Thesis-Hackmanit.pdf)
- Error-Based, Boolean-Based: [Successful Errors: New Code Injection and SSTI Techniques - Vladislav Korchagin - January 03, 2026](https://github.com/vladko312/Research_Successful_Errors/blob/main/README.md)

#### Rendered

![Rendered technique workflow](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/technique_Rendered.png?raw=true)

> Applicability: detection, exploitation

When the rendered template is displayed to the attacker, Rendered technique can be used to include the results of the injected code on the page.

#### Error-Based

![Error-Based technique workflow](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/technique_Error-Based.png?raw=true)

> Applicability: detection, exploitation

When the errors are verbosely displayed to the attacker, Error-Based technique can be used to trigger the error message containing the results of the injected code.

#### Boolean-Based

![Boolean-Based technique workflow](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/technique_Boolean-Based.png?raw=true)

> Applicability: detection, blind exploitation, blind data exfiltration

Boolean-Based technique can be used to conditionally trigger an error to indicate success or failure of the injected code.

#### Time-Based

![Time-Based technique workflow](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/technique_Time-Based.png?raw=true)

> Applicability: limited detection, blind exploitation, blind data exfiltration

Time-Based technique can be used to conditionally trigger the delay to indicate success or failure of the injected code.

Triggering the delay often requires guessing payloads for code evaluation or OS command execution.

#### Out of Bounds

> Applicability: limited detection, exploitation

Out of Bounds technique can be used to expose results of the injected code through other channels (e.g. by connecting to an attacker-controlled server).

This technique often requires guessing payloads for code evaluation or OS command execution.

#### Polyglot-Based

![Polyglot-Based technique workflow](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/technique_Polyglot-Based.png?raw=true)

> Applicability: detection

Polyglot-Based technique can be used to quickly determine the template engine by checking how it transforms different payloads.

### Universal Detection Payloads

Polyglot to trigger an error in presence of SSTI vulnerability:

```ps1
${{<%[%'"}}%\.
```

Common tags to test for SSTI with code evaluation:

```
{{ ... }}
${ ... }
#{ ... }
<%= ... %>
{ ... }
{{= ... }}
{= ... }
\n= ... \n
*{ ... }
@{ ... }
@( ... )
```

Rendered SSTI can be checked by using mathematical expressions inside the tags:

```
7 * 7
```

Error-Based SSTI can be checked by using this payload inside the tags:

```
(1/0).zxy.zxy
```

If the error caused by that payload is displayed verbosely, it can be checked to guess the language used for code evaluation:

| Error                         | Language          |
|-------------------------------|-------------------|
| ZeroDivisionError             | Python            |
| java.lang.ArithmeticException | Java              |
| ReferenceError                | NodeJS            |
| TypeError                     | NodeJS            |
| Division by zero              | PHP               |
| DivisionByZeroError           | PHP               |
| divided by 0                  | Ruby              |
| Arithmetic operation failed   | Freemarker (Java) |

To test for blind injections using Boolean-Based technique, the attacker can test pairs of similar payloads wrapped in tags, where one payload evaluates mathematical expression, while the other triggers syntax error:

| test | ok              | error           |
|------|-----------------|-----------------|
| 1    | `(3*4/2)`       | `3*)2(/4`       |
| 2    | `((7*8)/(2*4))` | `7)(*)8)(2/(*4` |

Using at least two pairs of payloads avoids false positives caused by external interference.

### Manual Detection and Exploitation

#### Identify the Vulnerable Input Field

The attacker first locates an input field, URL parameter, or any user-controllable part of the application that is passed into a server-side template without proper sanitization or escaping.

For example, the attacker might identify a web form, search bar, or template preview functionality that seems to return results based on dynamic user input.

**TIP**: Generated PDF files, invoices and emails usually use a template.

#### Inject Template Syntax

The attacker tests the identified input field by injecting template syntax specific to the template engine in use. Different web frameworks use different template engines (e.g., Jinja2 for Python, Twig for PHP, or FreeMarker for Java).

Common template expressions:

- `{{7*7}}` for Jinja2 (Python).
- `#{7*7}` for Thymeleaf (Java).

Find more template expressions in the page dedicated to the technology (PHP, Python, etc).

![SSTI cheatsheet workflow](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/serverside.png?raw=true)

In most cases, this polyglot payload will trigger an error in presence of a SSTI vulnerability:

```ps1
${{<%[%'"}}%\.
```

The [Hackmanit/Template Injection Table](https://github.com/Hackmanit/template-injection-table) is an interactive table containing the most efficient template injection polyglots along with the expected responses of the 44 most important template engines.

#### Enumerate the Template Engine

Based on the successful response, the attacker determines which template engine is being used. This step is critical because different template engines have different syntax, features, and potential for exploitation. The attacker may try different payloads to see which one executes, thereby identifying the engine.

- **Python**: Django, Jinja2, Mako, ...
- **Java**: Freemarker, Jinjava, Velocity, ...
- **Ruby**: ERB, Slim, ...

[The post "template-engines-injection-101" from @0xAwali](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756) summarize the syntax and detection method for most of the template engines for JavaScript, Python, Ruby, Java and PHP and how to differentiate between engines that use the same syntax.

#### Escalate to Code Execution

Once the template engine is identified, the attacker injects more complex expressions, aiming to execute server-side commands or arbitrary code.

## Labs

- [Root Me - Java - Server-side Template Injection](https://www.root-me.org/en/Challenges/Web-Server/Java-Server-side-Template-Injection)
- [Root Me - Python - Server-side Template Injection Introduction](https://www.root-me.org/en/Challenges/Web-Server/Python-Server-side-Template-Injection-Introduction)
- [Root Me - Python - Blind SSTI Filters Bypass](https://www.root-me.org/en/Challenges/Web-Server/Python-Blind-SSTI-Filters-Bypass)

## References

- [Server-Side Template Injection: RCE For The Modern Web App - James Kettle - August 05, 2015](https://portswigger.net/knowledgebase/papers/serversidetemplateinjection.pdf)
- [Improving the Detection and Identification of Template Engines for Large-Scale Template Injection Scanning - Maximilian Hildebrand - September 19, 2023](https://www.hackmanit.de/images/download/thesis/Improving-the-Detection-and-Identification-of-Template-Engines-for-Large-Scale-Template-Injection-Scanning-Maximilian-Hildebrand-Master-Thesis-Hackmanit.pdf)
- [Successful Errors: New Code Injection and SSTI Techniques - Vladislav Korchagin - January 03, 2026](https://github.com/vladko312/Research_Successful_Errors/blob/main/README.md)
- [A Pentester's Guide to Server Side Template Injection (SSTI) - Busra Demir - December 24, 2020](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)
- [Gaining Shell using Server Side Template Injection (SSTI) - David Valles - August 22, 2018](https://medium.com/@david.valles/gaining-shell-using-server-side-template-injection-ssti-81e29bb8e0f9)
- [Template Engines Injection 101 - Mahmoud M. Awali - November 1, 2024](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
- [Template Injection On Hardened Targets - Lucas 'BitK' Philippe - September 28, 2022](https://youtu.be/M0b_KA0OMFw)
