If you have upload access to a non /cgi-bin folder - upload a httpd.conf and configure your own interpreter.

Details from Busybox httpd.c

https://github.com/brgl/busybox/blob/abbf17abccbf832365d9acf1c280369ba7d5f8b2/networking/httpd.c#L60

> *.php:/path/php   # run xxx.php through an interpreter`

>  If a sub directory contains config file, it is parsed and merged with any existing settings as if it was appended to the original configuration.

Watch out for Windows CRLF line endings messing up your payload (you will just get 404 errors) - you can't see these in Burp :)  
