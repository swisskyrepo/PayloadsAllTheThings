# Collection of usefull scripts and tricks

## Dorks

Google Dork to find subdomains
```
site:*.domain.com -www
site:http://domain.com ext:php
site:http://domain.com filtype:pdf
```

## Scripts
Script to detect all phpinfo.php files in a range of IPs (CIDR can be found with a whois)
```
#!/bin/bash
for ipa in 98.13{6..9}.{0..255}.{0..255}; do
wget -t 1 -T 3 http://${ipa}/phpinfo.php; done &
```

Script to detect all .htpasswd files in a range of IPs
```
#!/bin/bash
for ipa in 98.13{6..9}.{0..255}.{0..255}; do
wget -t 1 -T 3 http://${ipa}/.htpasswd; done &
```


## Thanks to
* http://blog.it-securityguard.com/bugbounty-yahoo-phpinfo-php-disclosure-2/