# Encoding and Transformations

> Encoding and Transformations are techniques that change how data is represented or transferred without altering its core meaning. Common examples include URL encoding, Base64, HTML entity encoding, and Unicode transformations. Attackers use these methods as gadgets to bypass input filters, evade web application firewalls, or break out of sanitization routines.

## Summary

* [Unicode](#unicode)
    * [Unicode Normalization](#unicode-normalization)
    * [Punycode](#punycode)
* [Base64](#base64)
* [Labs](#labs)
* [References](#references)

## Unicode

Unicode is a universal character encoding standard used to represent text from virtually every writing system in the world. Each character (letters, numbers, symbols, emojis) is assigned a unique code point (for example, U+0041 for "A"). Unicode encoding formats like UTF-8 and UTF-16 specify how these code points are stored as bytes.

### Unicode Normalization

Unicode normalization is the process of converting Unicode text into a standardized, consistent form so that equivalent characters are represented the same way in memory.

[Unicode Normalization reference table](https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html)

* **NFC** (Normalization Form Canonical Composition): Combines decomposed sequences into precomposed characters where possible.
* **NFD** (Normalization Form Canonical Decomposition): Breaks characters into their decomposed forms (base + combining marks).
* **NFKC** (Normalization Form Compatibility Composition): Like NFC, but also replaces characters with compatibility equivalents (may change appearance/format).
* **NFKD** (Normalization Form Compatibility Decomposition): Like NFD, but also decomposes compatibility characters.

| Character    | Payload               | After Normalization   |
| ------------ | --------------------- | --------------------- |
| `‥` (U+2025) | `‥/‥/‥/etc/passwd` | `../../../etc/passwd` |
| `︰` (U+FE30) | `︰/︰/︰/etc/passwd` | `../../../etc/passwd` |
| `＇` (U+FF07) | `＇ or ＇1＇=＇1` | `' or '1'='1` |
| `＂` (U+FF02) | `＂ or ＂1＂=＂1` | `" or "1"="1` |
| `﹣` (U+FE63) | `admin'﹣﹣` | `admin'--` |
| `。` (U+3002) | `domain。com` | `domain.com` |
| `／` (U+FF0F) | `／／domain.com` | `//domain.com` |
| `＜` (U+FF1C) | `＜img src=a＞` | `<img src=a/>` |
| `﹛` (U+FE5B) | `﹛﹛3+3﹜﹜` | `{{3+3}}` |
| `［` (U+FF3B) | `［［5+5］］` | `[[5+5]]` |
| `＆` (U+FF06) | `＆＆whoami` | `&&whoami` |
| `ｐ` (U+FF50) | `shell.ｐʰｐ` | `shell.php` |
| `ʰ` (U+02B0) | `shell.ｐʰｐ` | `shell.php` |
| `ª` (U+00AA) | `ªdmin` | `admin` |

```py
import unicodedata
string = "ᴾᵃʸˡᵒᵃᵈˢ𝓐𝓵𝓵𝕋𝕙𝕖𝒯𝒽𝒾𝓃ℊ𝓈"
print ('NFC: ' + unicodedata.normalize('NFC', string))
print ('NFD: ' + unicodedata.normalize('NFD', string))
print ('NFKC: ' + unicodedata.normalize('NFKC', string))
print ('NFKD: ' + unicodedata.normalize('NFKD', string))
```

### Punycode

Punycode is a way to represent Unicode characters (including non-ASCII letters, symbols, and scripts) using only the limited set of ASCII characters (letters, digits, and hyphens).

It's mainly used in the Domain Name System (DNS), which traditionally supports only ASCII. Punycode allows internationalized domain names (IDNs), so that domain names can include characters from many languages by converting them into a safe ASCII form.

| Visible in Browser (IDN support) | Actual ASCII (Punycode) |
| -------------------------------- | ----------------------- |
| раypal.com                       | xn--ypal-43d9g.com      |
| paypal.com                       | paypal.com              |

In MySQL, similar character are treated as equal. This behavior can be abused in Password Reset, Forgot Password, and OAuth Provider sections.

```sql
SELECT 'a' = 'ᵃ';
+-------------+
| 'a' = 'ᵃ'   |
+-------------+
|           1 |
+-------------+
```

This trick works the SQL query uses `COLLATE utf8mb4_0900_as_cs`.

```sql
SELECT 'a' = 'ᵃ' COLLATE utf8mb4_0900_as_cs;
+----------------------------------------+
| 'a' = 'ᵃ' COLLATE utf8mb4_0900_as_cs   |
+----------------------------------------+
|                                      0 |
+----------------------------------------+
```

## Base64

Base64 encoding is a method for converting binary data (like images or files) or text with special characters into a readable string that uses only ASCII characters (A-Z, a-z, 0-9, +, and /). Every 3 bytes of input are divided into 4 groups of 6 bits and mapped to 4 Base64 characters. If the input isn't a multiple of 3 bytes, the output is padded with `=` characters.

```ps1
echo -n admin | base64                            
YWRtaW4=

echo -n YWRtaW4= | base64 -d
admin
```

## Labs

* [NahamCon - Puny-Code: 0-Click Account Takeover](https://github.com/VoorivexTeam/white-box-challenges/tree/main/punycode)
* [PentesterLab - Unicode and NFKC](https://pentesterlab.com/exercises/unicode-transform)

## References

* [Puny-Code, 0-Click Account Takeover - Voorivex - June 1, 2025](https://web.archive.org/web/20251211233427/https://blog.voorivex.team/puny-code-0-click-account-takeover)
* [Unicode normalization vulnerabilities - Lazar - September 30, 2021](https://web.archive.org/web/20251224043224/https://lazarv.com/posts/unicode-normalization-vulnerabilities/)
* [Unicode Normalization Vulnerabilities & the Special K Polyglot - AppCheck - September 2, 2019](https://web.archive.org/web/20190916002602/https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)
* [WAF Bypassing with Unicode Compatibility - Jorge Lajara - February 19, 2020](https://web.archive.org/web/20251230185141/https://jlajara.gitlab.io/Bypass_WAF_Unicode)
* [When "Zoë" !== "Zoë". Or why you need to normalize Unicode strings - Alessandro Segala - March 11, 2019](https://web.archive.org/web/20260128220322/https://withblue.ink/2019/03/11/why-you-need-to-normalize-unicode-strings.html)
