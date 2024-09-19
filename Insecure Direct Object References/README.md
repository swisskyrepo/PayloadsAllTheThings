# Insecure Direct Object References

> Insecure Direct Object References occur when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability attackers can bypass authorization and access resources in the system directly, for example database records or files. - OWASP


## Summary

* [Tools](#tools)
* [Labs](#labs)
* [Exploit](#exploit)
    * [Numeric Value Parameter](#numeric-value-parameter)
    * [Common Identifiers Parameter](#common-identifiers-parameter) 
    * [Weak Pseudo Random Number Generator](#weak-pseudo-random-number-generator) 
    * [Hashed Parameter](#hashed-parameter)
    * [Wildcard Parameter](#wildcard-parameter)
    * [IDOR Tips](#idor-tips)
* [References](#references)


## Tools

- [PortSwigger/BApp Store > Authz](https://portswigger.net/bappstore/4316cc18ac5f434884b2089831c7d19e)
- [PortSwigger/BApp Store > AuthMatrix](https://portswigger.net/bappstore/30d8ee9f40c041b0bfec67441aad158e)
- [PortSwigger/BApp Store > Autorize](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f)


## Labs

* [PortSwigger - Insecure Direct Object References](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)


## Exploit

IDOR stands for Insecure Direct Object Reference. It's a type of security vulnerability that arises when an application provides direct access to objects based on user-supplied input. As a result, attackers can bypass authorization and access resources in the system directly, potentially leading to unauthorized information disclosure, modification, or deletion.

**Example of IDOR**

Imagine a web application that allows users to view their profile by clicking a link `https://example.com/profile?user_id=123`:

```php
<?php
    $user_id = $_GET['user_id'];
    $user_info = get_user_info($user_id);
    ...
```

Here, `user_id=123` is a direct reference to a specific user's profile. If the application doesn't properly check that the logged-in user has the right to view the profile associated with `user_id=123`, an attacker could simply change the `user_id` parameter to view other users' profiles:

```ps1
https://example.com/profile?user_id=124
```

![https://lh5.googleusercontent.com/VmLyyGH7dGxUOl60h97Lr57F7dcnDD8DmUMCZTD28BKivVI51BLPIqL0RmcxMPsmgXgvAqY8WcQ-Jyv5FhRiCBueX9Wj0HSCBhE-_SvrDdA6_wvDmtMSizlRsHNvTJHuy36LG47lstLpTqLK](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Direct%20Object%20References/Images/idor.png)


### Numeric Value Parameter

Increment and decrement these values to access sensitive information.

* Decimal value: `287789`, `287790`, `287791`, ...
* Hexadecimal: `0x4642d`, `0x4642e`, `0x4642f`, ...
* Unix epoch timestamp: `1695574808`, `1695575098`, ...

**Examples** 

* [HackerOne - IDOR to view User Order Information - meals](https://hackerone.com/reports/287789)
* [HackerOne - Delete messages via IDOR - naaash](https://hackerone.com/reports/697412)

### Common Identifiers Parameter

Some identifiers can be guessed like names and emails, they might grant you access to customer data.

* Name: `john`, `doe`, `john.doe`, ...
* Email: `john.doe@mail.com`
* Base64 encoded value: `am9obi5kb2VAbWFpbC5jb20=`

**Examples** 

* [HackerOne - Insecure Direct Object Reference (IDOR) - Delete Campaigns - datph4m](https://hackerone.com/reports/1969141)


### Weak Pseudo Random Number Generator

* UUID/GUID v1 can be predicted if you know the time they were created: `95f6e264-bb00-11ec-8833-00155d01ef00`
* MongoDB Object Ids are generated in a predictable manner: `5ae9b90a2c144b9def01ec37`
    * a 4-byte value representing the seconds since the Unix epoch
    * a 3-byte machine identifier
    * a 2-byte process id
    * a 3-byte counter, starting with a random value

**Examples** 

* [HackerOne - IDOR allowing to read another user's token on the Social Media Ads service - a_d_a_m](https://hackerone.com/reports/1464168)
* [IDOR through MongoDB Object IDs Prediction](https://techkranti.com/idor-through-mongodb-object-ids-prediction/)


### Hashed Parameter

Sometimes we see websites using hashed values to generate a random user id or token, like `sha1(username)`, `md5(email)`, ...

* MD5: `098f6bcd4621d373cade4e832627b4f6`
* SHA1: `a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`
* SHA2: `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`

**Examples** 

* [IDOR with Predictable HMAC Generation - DiceCTF 2022 - CryptoCat](https://youtu.be/Og5_5tEg6M0)


### Wildcard Parameter

Send a wildcard (`*`, `%`, `.`, `_`) instead of an ID, some backend might respond with the data of all the users.

* `GET /api/users/* HTTP/1.1`
* `GET /api/users/% HTTP/1.1`
* `GET /api/users/_ HTTP/1.1`
* `GET /api/users/. HTTP/1.1`


**Examples** 

* [TODO]()


### IDOR Tips

* Change the HTTP request: `POST → PUT`
* Change the content type: `XML → JSON`
* Transform numerical values to arrays: `{"id":19} → {"id":[19]}`
* Use Parameter Pollution: `user_id=hacker_id&user_id=victim_id`


## References

* [OWASP - Testing for Insecure Direct Object References (OTG-AUTHZ-004)](https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004))
* [OWASP - Insecure Direct Object Reference Prevention Cheat Sheet](https://www.owasp.org/index.php/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet)
* [BUGCROWD - How-To: Find IDOR (Insecure Direct Object Reference) Vulnerabilities for large bounty rewards - Sam Houton](https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/)
* [Manipulation of ETH balance](https://www.vicompany.nl/magazine/from-christmas-present-in-the-blockchain-to-massive-bug-bounty)
* [Viewing private Airbnb Messages](http://buer.haus/2017/03/31/airbnb-web-to-app-phone-notification-idor-to-view-everyones-airbnb-messages/) 
* [Hunting Insecure Direct Object Reference Vulnerabilities for Fun and Profit (PART-1) - Mohammed Abdul Raheem - Feb 2, 2018](https://codeburst.io/hunting-insecure-direct-object-reference-vulnerabilities-for-fun-and-profit-part-1-f338c6a52782)
* [IDOR - how to predict an identifier? Bug bounty case study - Bug Bounty Reports Explained - ](https://youtu.be/wx5TwS0Dres)
* [Testing for IDORs - PortSwigger](https://portswigger.net/burp/documentation/desktop/testing-workflow/access-controls/testing-for-idors)
* [Insecure direct object references (IDOR) - PortSwigger](https://portswigger.net/web-security/access-control/idor)
* [The Rise of IDOR - HackerOne - April 2nd, 2021](https://www.hackerone.com/company-news/rise-idor)