# Miscellaneous & Tricks

All the tricks that couldn't be classified somewhere else.

## Send a message to another user

```powershell
# Windows
PS C:\> msg Swissky /SERVER:CRASHLAB "Stop rebooting the XXXX service !"
PS C:\> msg * /V /W /SERVER:CRASHLAB "Hello all !"

# Linux
$ wall "Stop messing with the XXX service !"
$ wall -n "System will go down for 2 hours maintenance at 13:00 PM"  # "-n" only for root
$ who
$ write root pts/2	# press Ctrl+D  after typing the message. 
```

## CrackMapExec Credential Database

```ps1
cmedb (default) > workspace create test
cmedb (test) > workspace default
cmedb (test) > proto smb
cmedb (test)(smb) > creds
cmedb (test)(smb) > export creds csv /tmp/creds
```