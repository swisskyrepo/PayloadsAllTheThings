# Google Web Toolkit

> Google Web Toolkit (GWT), also known as GWT Web Toolkit, is an open-source set of tools that allows web developers to create and maintain JavaScript front-end applications using Java. It was originally developed by Google and had its initial release on May 16, 2006.


## Summary

* [Tools](#tools)
* [Methodology](#methodology)
* [References](#references)


## Tools

* [FSecureLABS/GWTMap](https://github.com/FSecureLABS/GWTMap) - GWTMap is a tool to help map the attack surface of Google Web Toolkit (GWT) based applications. 
* [GDSSecurity/GWT-Penetration-Testing-Toolset](https://github.com/GDSSecurity/GWT-Penetration-Testing-Toolset) - A set of tools made to assist in penetration testing GWT applications. 


## Methodology

* Enumerate the methods of a remote application via it's bootstrap file and create a local backup of the code (selects permutation at random):
    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup
    ```
* Enumerate the methods of a remote application via a specific code permutation
    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
    ```
* Enumerate the methods whilst routing traffic through an HTTP proxy:
    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup -p http://127.0.0.1:8080
    ```
* Enumerate the methods of a local copy (a file) of any given permutation:
    ```ps1
    ./gwtmap.py -F test_data/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
    ```
* Filter output to a specific service or method: 
    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login
    ```
* Generate RPC payloads for all methods of the filtered service, with coloured output
    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService --rpc --color
    ```
* Automatically test (probe) the generate RPC request for the filtered service method
    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login --rpc --probe
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter TestService.testDetails --rpc --probe
    ```


## References

- [From Serialized to Shell :: Exploiting Google Web Toolkit with EL Injection - Stevent Seeley - May 22, 2017](https://srcincite.io/blog/2017/05/22/from-serialized-to-shell-auditing-google-web-toolkit-with-el-injection.html)
- [Hacking a Google Web Toolkit application - thehackerish - April 22, 2021](https://thehackerish.com/hacking-a-google-web-toolkit-application/)