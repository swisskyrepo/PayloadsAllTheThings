# Upload

Uploaded files may pose a significant risk if not handled correctly. A remote attacker could send a multipart/form-data POST request with a specially-crafted filename or mime type and execute arbitrary code.

## Tools
- [Fuxploider](https://github.com/almandin/fuxploider)

## Exploits

### PHP Extension

```powershell
.php
.php3
.php4
.php5
.php7

Less known extensions
.pht
.phar
.phpt
.pgif
.phtml
.phtm

Double extensions
.jpeg.php
.jpg.php
.png.php
```

### Upload tricks

- Null byte (eg: shell.php%00.gif, shell.php%00.png), works well against `pathinfo()`
- Mime type, change `Content-Type : application/x-php` or `Content-Type : application/octet-stream` to `Content-Type : image/gif`

### Picture upload with LFI

Valid pictures hosting PHP code. Upload the picture and use a local file inclusion to execute the code. The shell can be called with the following command : `curl 'http://localhost/test.php?0=system' --data "1='ls'"`.

- Picture Metadata, hide the payload inside a comment tag in the metadata.
- Picture Resize, hide the payload within the compression algorithm in order to bypass a resize. Also defeating `getimagesize()` and `imagecreatefromgif()`.

### Configuration Files

- .htaccess
- web.config
- httpd.conf
- \_\_init\_\_.py


### CVE - Image Tragik

```powershell
HTTP Request
Reverse Shell
Touch command
```

## References

* Bulletproof Jpegs Generator - Damien "virtualabs" Cauquil
* [BookFresh Tricky File Upload Bypass to RCE, NOV 29, 2014 - AHMED ABOUL-ELA](https://secgeek.net/bookfresh-vulnerability/)
* [Encoding Web Shells in PNG IDAT chunks, 04-06-2012, phil](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
* [La PNG qui se prenait pour du PHP, 23 février 2014](https://phil242.wordpress.com/2014/02/23/la-png-qui-se-prenait-pour-du-php/)
