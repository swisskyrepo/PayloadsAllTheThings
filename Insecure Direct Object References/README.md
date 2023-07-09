# Insecure Direct Object References

> Insecure Direct Object References occur when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability attackers can bypass authorization and access resources in the system directly, for example database records or files. - OWASP


## Summary

* [Tools](#tools)
* [Exploit](#exploit)
    * [IDOR Tips](#idor-tips)
* [Examples](#examples)
* [Labs](#labs)
* [References](#references)


## Tools

- [BApp Store > Authz](https://portswigger.net/bappstore/4316cc18ac5f434884b2089831c7d19e)
- [BApp Store > AuthMatrix](https://portswigger.net/bappstore/30d8ee9f40c041b0bfec67441aad158e)
- [BApp Store > Autorize](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f)


## Exploit

For instance, consider a URL like `https://example.com/account?userid=123`. In this case, `123` is a direct object reference to a specific user's account. If the application doesn't properly check that the logged-in user has the right to access the account related to `userid=123`, then any user could potentially change the userid in the URL to access other users' accounts.

![https://lh5.googleusercontent.com/VmLyyGH7dGxUOl60h97Lr57F7dcnDD8DmUMCZTD28BKivVI51BLPIqL0RmcxMPsmgXgvAqY8WcQ-Jyv5FhRiCBueX9Wj0HSCBhE-_SvrDdA6_wvDmtMSizlRsHNvTJHuy36LG47lstLpTqLK](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Direct%20Object%20References/Images/idor.png)

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


### IDOR Tips

* Change the HTTP request: POST → PUT
* Change the content type: XML → JSON
* Increment/decrement numerical values (1,2,3,..)
* GUID/UUID might be weak
* Transform numerical values to arrays: `{"id":19} → {"id":[19]}`


## Examples

* [HackerOne - IDOR to view User Order Information - meals](https://hackerone.com/reports/287789)
* [HackerOne - IDOR on HackerOne Feedback Review - japz](https://hackerone.com/reports/262661)


## Labs

* [PortSwigger - Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)


## References

* [OWASP - Testing for Insecure Direct Object References (OTG-AUTHZ-004)](https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004))
* [OWASP - Insecure Direct Object Reference Prevention Cheat Sheet](https://www.owasp.org/index.php/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet)
* [BUGCROWD - How-To: Find IDOR (Insecure Direct Object Reference) Vulnerabilities for large bounty rewards - Sam Houton](https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/)
* [IDOR tweet as any user](http://kedrisec.com/twitter-publish-by-any-user/) by kedrisec
* [Manipulation of ETH balance](https://www.vicompany.nl/magazine/from-christmas-present-in-the-blockchain-to-massive-bug-bounty)
* [Viewing private Airbnb Messages](http://buer.haus/2017/03/31/airbnb-web-to-app-phone-notification-idor-to-view-everyones-airbnb-messages/) 
* [Hunting Insecure Direct Object Reference Vulnerabilities for Fun and Profit (PART-1) - Mohammed Abdul Raheem - Feb 2, 2018](https://codeburst.io/hunting-insecure-direct-object-reference-vulnerabilities-for-fun-and-profit-part-1-f338c6a52782)