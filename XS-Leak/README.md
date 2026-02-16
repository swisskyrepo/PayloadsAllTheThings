# XS-Leak

> Cross-Site Leaks (XS-Leaks) are side-channel vulnerabilities allowing attackers to infer sensitive information from a target origin without reading the response body. They exploit browser behaviors, timing differences, and observable side effects rather than traditional XSS data exfiltration.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Attack Primitives](#attack-primitives)
    * [XS-Search](#xs-search)
* [Cross-site Oracles](#cross-site-oracles)
    * [Timing Attacks](#timing-attacks)
    * [Frame Counting](#frame-counting)
    * [Cache Probing](#cache-probing)
    * [Known Oracles](#known-oracles)
* [Labs](#labs)
* [References](#references)

## Tools

* [RUB-NDS/xsinator.com](https://github.com/RUB-NDS/xsinator.com) - XS-Leak Browser Test Suite.
* [RUB-NDS/AutoLeak](https://github.com/RUB-NDS/AutoLeak) - Find XS-Leaks in the browser by diffing DOM-Graphs in two states.

## Methodology

### Attack Primitives

Unlike classic CORS or XSS attacks, XS-Leaks rely on observable browser behavior:

| Primitive   | Leaks                      |
| ----------- | -------------------------- |
| Timing      | Resource size / complexity |
| Frame count | Content differences        |
| Errors      | Access control decisions   |
| Cache       | Previous visits            |
| Navigation  | Auth state                 |
| Rendering   | Text length                |

### XS-Search

XS-Search attacks abuse Query-Based Search Systems to leak user information. By measuring the side effects of a search query (e.g., response time, frame count, or error events), an attacker can infer whether a search returned results or not. This boolean oracle can be used to brute-force sensitive data character by character.

**Examples**:

* Opening 50 tabs and use the timing difference from an iframe CSP violation in the search results page to bruteforce the flag character by character.

## Cross-site Oracles

### Timing Attacks

In a timing attack, an attacker seeks to uncover sensitive information by observing how long a system takes to respond to particular requests. They deploy carefully designed scripts to the target application to execute API calls, send AJAX requests, or initiate cross-origin resource sharing (CORS) interactions. By measuring and comparing the response times of these operations, the attacker can deduce insights about the system’s internal behavior, data validation processes, or underlying security controls.

### Frame Counting

If a page loads different numbers of iframes based on the user's state (e.g., search results), an attacker can count them to infer data.

```js
// Get a reference to the window
var win = window.open('https://example.org');

// Wait for the page to load
setTimeout(() => {
  // Read the number of iframes loaded
  console.log("%d iframes detected", win.length);
}, 2000);
```

### Cache Probing

In a cache probing attack, a malicious website attempts to determine whether a specific resource from a target site is already stored in the victim’s browser cache. The attacker causes the browser to request a resource (for example, an image, script, or endpoint) that may only be cached if the user is authenticated or has previously visited a particular page. By measuring how quickly the resource loads, or by observing differences in behavior between a cached and non-cached response, the attacker can infer sensitive information.

### Known Oracles

* [Cache Leak (CORS)](https://xsinator.com/testing.html#Cache%20Leak%20(CORS)) - Detect resources loaded by page. Cache is deleted with CORS error.
* [Cache Leak (POST)](https://xsinator.com/testing.html#Cache%20Leak%20(POST)) - Detect resources loaded by page. Cache is deleted with a POST request.
* [ContentDocument X-Frame Leak](https://xsinator.com/testing.html#ContentDocument%20X-Frame%20Leak) - Detect X-Frame-Options with ContentDocument.
* [COOP Leak](https://xsinator.com/testing.html#COOP%20Leak) - Detect Cross-Origin-Opener-Policy header with popup.
* [CORB Leak](https://xsinator.com/testing.html#CORB%20Leak) - Detect X-Content-Type-Options in combination with specific content type using CORB.
* [CORP Leak](https://xsinator.com/testing.html#CORP%20Leak) - Detect Cross-Origin-Resource-Policy header with fetch.
* [CORS Error Leak](https://xsinator.com/testing.html#CORS%20Error%20Leak) - Leak redirect target URL with CORS error.
* [CSP Directive Leak](https://xsinator.com/testing.html#CSP%20Directive%20Leak) - Detect CSP directives with CSP iframe attribute.
* [CSP Redirect Detection](https://xsinator.com/testing.html#CSP%20Redirect%20Detection) - Detect cross-origin redirects with CSP violation event.
* [CSP Violation Leak](https://xsinator.com/testing.html#CSP%20Violation%20Leak) - Leak cross-origin redirect target with CSP violation event.
* [CSS Property Leak](https://xsinator.com/testing.html#CSS%20Property%20Leak) - Leak CSS rules with getComputedStyle.
* [Disk cache grooming](https://gist.github.com/parrot409/e3b546d3b76e9f9044d22456e4cc8622)
* [Download Detection](https://xsinator.com/testing.html#Download%20Detection) - Detect downloads (Content-Disposition header).
* [Duration Redirect Leak](https://xsinator.com/testing.html#Duration%20Redirect%20Leak) - Detect cross-origin redirects by checking the duration.
* [ETag header length](https://blog.arkark.dev/2025/12/26/etag-length-leak) - Detect response body size with ETag header length
* [Event Handler Leak (Object)](https://xsinator.com/testing.html#Event%20Handler%20Leak%20(Object)) - Detect errors with onload/onerror with object.
* [Event Handler Leak (Script)](https://xsinator.com/testing.html#Event%20Handler%20Leak%20(Script)) - Detect errors with onload/onerror with script.
* [Event Handler Leak (Stylesheet)](https://xsinator.com/testing.html#Event%20Handler%20Leak%20(Stylesheet)) - Detect errors with onload/onerror with stylesheet.
* [Fetch Redirect Leak](https://xsinator.com/testing.html#Fetch%20Redirect%20Leak) - Detect HTTP redirects with Fetch API.
* [Frame Count Leak](https://xsinator.com/testing.html#Frame%20Count%20Leak) - Detect the number of iframes on a page.
* [History Length Leak](https://xsinator.com/testing.html#History%20Length%20Leak) - Detect javascript redirects with History API.
* [Id Attribute Leak](https://xsinator.com/testing.html#Id%20Attribute%20Leak) - Leak id attribute of focusable HTML elements with onblur.
* [Max Redirect Leak](https://xsinator.com/testing.html#Max%20Redirect%20Leak) - Detect server redirect by abusing max redirect limit.
* [Media Dimensions Leak](https://xsinator.com/testing.html#Media%20Dimensions%20Leak) - Leak dimensions of images or videos.
* [Media Duration Leak](https://xsinator.com/testing.html#Media%20Duration%20Leak) - Leak duration of audio or videos.
* [MediaError Leak](https://xsinator.com/testing.html#MediaError%20Leak) - Detect status codes with MediaError message.
* [Payment API Leak](https://xsinator.com/testing.html#Payment%20API%20Leak) - Detect if another tab is using the Payment API.
* [Performance API CORP Leak](https://xsinator.com/testing.html#Performance%20API%20CORP%20Leak) - Detect Cross-Origin-Resource-Policy header with Performance API.
* [Performance API Download Detection](https://xsinator.com/testing.html#Performance%20API%20Download%20Detection) - Detect downloads (Content-Disposition header) with Performance API.
* [Performance API Empty Page Leak](https://xsinator.com/testing.html#Performance%20API%20Empty%20Page%20Leak) - Detect empty responses with Performance API.
* [Performance API Error Leak](https://xsinator.com/testing.html#Performance%20API%20Error%20Leak) - Detect errors with Performance API.
* [Performance API X-Frame Leak](https://xsinator.com/testing.html#Performance%20API%20X-Frame%20Leak) - Detect X-Frame-Options with Performance API.
* [Performance API XSS Auditor Leak](https://xsinator.com/testing.html#Performance%20API%20XSS%20Auditor%20Leak) - Detect scripts/event handlers in a page with Performance API.
* [Redirect Start Leak](https://xsinator.com/testing.html#Redirect%20Start%20Leak) - Detect cross-origin HTTP redirects by checking redirectStart time.
* [Request Merging Error Leak](https://xsinator.com/testing.html#Request%20Merging%20Error%20Leak) - Detect errors with request merging.
* [SRI Error Leak](https://xsinator.com/testing.html#SRI%20Error%20Leak) - Leak content length with SRI error.
* [Style Reload Error Leak](https://xsinator.com/testing.html#Style%20Reload%20Error%20Leak) - Detect errors with style reload bug.
* [URL Max Length Leak](https://xsinator.com/testing.html#URL%20Max%20Length%20Leak) - Detect server redirect by abusing URL max length.
* [WebSocket Leak (FF)](https://xsinator.com/testing.html#WebSocket%20Leak%20(FF)) - Detect the number of websockets on a page by exausting the socket limit.
* [WebSocket Leak (GC)](https://xsinator.com/testing.html#WebSocket%20Leak%20(GC)) - Detect the number of websockets on a page by exausting the socket limit.

## Labs

* [Root Me - XS Leaks](https://www.root-me.org/en/Challenges/Web-Client/XS-Leaks)

## References

* [2025 SECCON CTF 14 Quals Web Challenges Writeup - RewriteLab - December 31, 2025](https://research.rewritelab.org/2025/12/31/%5BENG%5D%202025%20SECCON%20CTF%2014%20Quals%20Web%20Challenges%20Writeup/)
* [ASIS CTF Finals 2024 - arkark - December 30, 2024](https://blog.arkark.dev/2024/12/30/asisctf-finals#web-fire-leak)
* [Cross-Site ETag Length Leak - Takeshi Kaneko - December 26, 2025](https://blog.arkark.dev/2025/12/26/etag-length-leak)
* [Exfiltration of secrets using an XS-Leaks - HackTM Secrets - xanhacks - February 19, 2023](https://www.xanhacks.xyz/p/secrets-hacktmctf/)
* [Impossible Leak - SECCON 2025 Quals - parrot409 - December 14, 2025](https://gist.github.com/parrot409/e3b546d3b76e9f9044d22456e4cc8622)
* [justCTF 2022 - Baby XSLeak Write-up - aszx87410 - June 14, 2022](https://blog.huli.tw/2022/06/14/en/justctf-2022-xsleak-writeup/)
* [Secret Note Keeper (xs-leaks) Facebook CTF 2019 - Abdillah Muhamad - July 3, 2019](https://abdilahrf.github.io/ctf/writeup-secret-note-keeper-fbctf-2019)
* [SekaiCTF 2023 - Leakless Note - Kalmarunionen - September 5, 2023](https://www.kalmarunionen.dk/writeups/2023/sekai/leakless-notes/)
* [XS-Leak: Leaking IDs using focus - Gareth Heyes - October 8, 2019](https://portswigger.net/research/xs-leak-leaking-ids-using-focus)
