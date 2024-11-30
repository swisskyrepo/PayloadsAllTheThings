# Zip Slip

> The vulnerability is exploited using a specially crafted archive that holds directory traversal filenames (e.g. ../../shell.php). The Zip Slip vulnerability can affect numerous archive formats, including tar, jar, war, cpio, apk, rar and 7z. The attacker can then overwrite executable files and either invoke them remotely or wait for the system or user to call them, thus achieving remote command execution on the victim’s machine.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Additional Notes](#additional-notes)
* [References](#references)


## Tools

* [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc) - Create tar/zip archives that can exploit directory traversal vulnerabilities
* [usdAG/slipit](https://github.com/usdAG/slipit) - Utility for creating ZipSlip archives


## Methodology

The Zip Slip vulnerability is a critical security flaw that affects the handling of archive files, such as ZIP, TAR, or other compressed file formats. This vulnerability allows an attacker to write arbitrary files outside of the intended extraction directory, potentially overwriting critical system files, executing malicious code, or gaining unauthorized access to sensitive information.

**Example**: Suppose an attacker creates a ZIP file with the following structure:

```
malicious.zip
  ├── ../../../../etc/passwd
  ├── ../../../../usr/local/bin/malicious_script.sh
```

When a vulnerable application extracts `malicious.zip`, the files are written to `/etc/passwd` and /`usr/local/bin/malicious_script.sh` instead of being contained within the extraction directory. This can have severe consequences, such as corrupting system files or executing malicious scripts.


* Using [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc):
    ```python
    python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15
    ```

* Creating a ZIP archive containing a symbolic link:

    ```ps1
    ln -s ../../../index.php symindex.txt
    zip --symlinks test.zip symindex.txt
    ```

For a list of affected libraries and projects, visit [snyk/zip-slip-vulnerability](https://github.com/snyk/zip-slip-vulnerability)


## References

* [Zip Slip - Snyk - June 5, 2018](https://github.com/snyk/zip-slip-vulnerability)
* [Zip Slip Vulnerability - Snyk - April 15, 2018](https://snyk.io/research/zip-slip-vulnerability)
