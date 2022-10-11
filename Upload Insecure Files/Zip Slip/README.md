# Zip Slip

> The vulnerability is exploited using a specially crafted archive that holds directory traversal filenames (e.g. ../../shell.php). The Zip Slip vulnerability can affect numerous archive formats, including tar, jar, war, cpio, apk, rar and 7z. The attacker can then overwrite executable files and either invoke them remotely or wait for the system or user to call them, thus achieving remote command execution on the victim’s machine. 

## Summary

* [Detection](#detection)
* [Tools](#tools)
* [Exploits](#exploits)
  * [Basic Exploit](#basic-exploit)
* [Additional Notes](#additional-notes)

## Detection

- Any zip upload page on the application

## Tools

- [evilarc](https://github.com/ptoomey3/evilarc)
- [slipit](https://github.com/usdAG/slipit)

## Exploits

### Basic Exploit

Using evilarc:
```python
python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15
```

### Additional Notes
- For affected libraries and projects, visit https://github.com/snyk/zip-slip-vulnerability

## References

- [Zip Slip Vulnerability - Snyk Ltd, 2019](https://snyk.io/research/zip-slip-vulnerability)
- [Zip Slip - snyk, 2019](https://github.com/snyk/zip-slip-vulnerability)
