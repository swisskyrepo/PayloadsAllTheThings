# Insecure Direct Object References

> Insecure Direct Object References occur when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability attackers can bypass authorization and access resources in the system directly, for example database records or files.  - OWASP

Tools :

- Burp Suite plugin Authz
- Burp Suite plugin AuthMatrix
- Burp Suite plugin Authorize

## Exploit

![https://lh5.googleusercontent.com/VmLyyGH7dGxUOl60h97Lr57F7dcnDD8DmUMCZTD28BKivVI51BLPIqL0RmcxMPsmgXgvAqY8WcQ-Jyv5FhRiCBueX9Wj0HSCBhE-_SvrDdA6_wvDmtMSizlRsHNvTJHuy36LG47lstLpTqLK](https://lh5.googleusercontent.com/VmLyyGH7dGxUOl60h97Lr57F7dcnDD8DmUMCZTD28BKivVI51BLPIqL0RmcxMPsmgXgvAqY8WcQ-Jyv5FhRiCBueX9Wj0HSCBhE-_SvrDdA6_wvDmtMSizlRsHNvTJHuy36LG47lstLpTqLK)

The value of a parameter is used directly to retrieve a database record.

```powershell
http://foo.bar/somepage?invoice=12345
```

The value of a parameter is used directly to perform an operation in the system

```powershell
http://foo.bar/changepassword?user=someuser
```

The value of a parameter is used directly to retrieve a file system resource

```powershell
http://foo.bar/showImage?img=img00011
```

The value of a parameter is used directly to access application functionality

```powershell
http://foo.bar/accessPage?menuitem=12
```

## Examples

* [HackerOne - IDOR to view User Order Information - meals](https://hackerone.com/reports/287789)
* [HackerOne - IDOR on HackerOne Feedback Review - japz](https://hackerone.com/reports/262661)

## Thanks to

* [OWASP - Testing for Insecure Direct Object References (OTG-AUTHZ-004)](https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004))
* [OWASP - Insecure Direct Object Reference Prevention Cheat Sheet](https://www.owasp.org/index.php/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet)
* [BUGCROWD - How-To: Find IDOR (Insecure Direct Object Reference) Vulnerabilities for large bounty rewards - Sam Houton](https://www.bugcrowd.com/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/)