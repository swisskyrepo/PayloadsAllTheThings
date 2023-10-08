# Clickjacking: Web Application Security Vulnerability

> Clickjacking is a type of web security vulnerability where a malicious website tricks a user into clicking on something different from what the user perceives,
> potentially causing the user to perform unintended actions without their knowledge or consent. Users are tricked into performing all sorts of unintended actions
> are such as typing in the password, clicking on ‘Delete my account’ button, liking a post, deleting a post, commenting on a blog. In other words all the actions
> that a normal user can do on a legitimate website can be done using clickjacking.

## Summary
* [Tools](#tools)
* [Methodology](#methodology)
  * [UI Redressing](#ui-redressing)
  * [Invisible Frames](#invisible-frames)
  * [Button/Form Hijacking](#button-form-hijacking)
* [Filter Bypasses](#filter-bypasses)
* [Practice Environments](#practice-environments)
* [Reference](#references)

## Tools
* [Burp Suite](https://portswigger.net/burp)
* [OWASP ZAP](https://github.com/zaproxy/zaproxy)
* [Clickjack](https://github.com/machine1337/clickjack)

## Methodology

### UI Redressing
UI Redressing is a Clickjacking technique where an attacker overlays a transparent UI element on top of a legitimate website or application. 
The transparent UI element contains malicious content or actions that are visually hidden from the user. By manipulating the transparency and positioning of elements, 
the attacker can trick the user into interacting with the hidden content, believing they are interacting with the visible interface.
* **How UI Redressing Works:**
  * Overlaying Transparent Element: The attacker creates a transparent HTML element (usually a `<div>`) that covers the entire visible area of a legitimate website. This element is made transparent using CSS properties like `opacity: 0;`.
  * Positioning and Layering: By setting the CSS properties such as `position: absolute; top: 0; left: 0;`, the transparent element is positioned to cover the entire viewport. Since it's transparent, the user doesn't see it.
  * Misleading User Interaction: The attacker places deceptive elements within the transparent container, such as fake buttons, links, or forms. These elements perform actions when clicked, but the user is unaware of their presence due to the overlaying transparent UI element.
  * User Interaction: When the user interacts with the visible interface, they are unknowingly interacting with the hidden elements due to the transparent overlay. This interaction can lead to unintended actions or unauthorized operations.
```html
<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">
  <a href="malicious-link">Click me</a>
</div>
```

### Invisible Frames
Invisible Frames is a Clickjacking technique where attackers use hidden iframes to trick users into interacting with content from another website unknowingly. 
These iframes are made invisible by setting their dimensions to zero (height: 0; width: 0;) and removing their borders (border: none;). 
The content inside these invisible frames can be malicious, such as phishing forms, malware downloads, or any other harmful actions.

* **How Invisible Frames Work:**
  * Hidden IFrame Creation: The attacker includes an `<iframe>` element in a webpage, setting its dimensions to zero and removing its border, making it invisible to the user.
    ```html
    <iframe src="malicious-site" style="opacity: 0; height: 0; width: 0; border: none;"></iframe>
    ```
  * Loading Malicious Content: The src attribute of the iframe points to a malicious website or resource controlled by the attacker. This content is loaded silently without the user's knowledge because the iframe is invisible.
  * User Interaction: The attacker overlays enticing elements on top of the invisible iframe, making it seem like the user is interacting with the visible interface. For instance, the attacker might position a transparent button over the invisible iframe. When the user clicks the button, they are essentially clicking on the hidden content within the iframe.
  * Unintended Actions: Since the user is unaware of the invisible iframe, their interactions can lead to unintended actions, such as submitting forms, clicking on malicious links, or even performing financial transactions without their consent.


### Button/Form Hijacking
```html
<button onclick="submitForm()">Click me</button>
<form action="legitimate-site" method="POST" id="hidden-form">
  <!-- Hidden form fields -->
</form>
<script>
  function submitForm() {
    document.getElementById('hidden-form').submit();
  }
</script>
```

## Preventive Measures

### Implement X-Frame-Options Header
Implement the X-Frame-Options header with the DENY or SAMEORIGIN directive to prevent your website from being embedded within an iframe without your consent.
```apache
Header always append X-Frame-Options SAMEORIGIN
```

### Content Security Policy (CSP)
Use CSP to control the sources from which content can be loaded on your website, including scripts, styles, and frames. 
Define a strong CSP policy to prevent unauthorized framing and loading of external resources.
Example in HTML meta tag:
```html
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'self';">
```






## Practice Environments
* [OWASP WebGoat](https://owasp.org/www-project-webgoat/)

## References
* [Clickjacker.io](https://clickjacker.io)
* [Portswigger](https://portswigger.net/web-security/clickjacking)
* [Synopsys](https://www.synopsys.com/glossary/what-is-clickjacking.html#B)
* [OWASP](https://owasp.org/www-community/attacks/Clickjacking)
