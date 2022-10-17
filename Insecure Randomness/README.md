# Insecure Randomness

## Summary

* [GUID / UUID](#guid--uuid)
    * [GUID Versions](#guid-versions)
    * [Tools](#tools)
* [References](#references)

## GUID / UUID

### GUID Versions

Version identification: `xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx` 
The four-bit M and the 1- to 3-bit N fields code the format of the UUID itself.

| Version  | Notes  |
|----------|--------|
| 0 | Only `00000000-0000-0000-0000-000000000000` |
| 1 | based on time, or clock sequence |
| 2 | reserved in the RFC 4122, but ommitted in many implementations |
| 3 | based on a MD5 hash |
| 4 | randomly generated |
| 5 | based on a SHA1 hash |

### Tools

* [intruder-io/guidtool](https://github.com/intruder-io/guidtool) - A tool to inspect and attack version 1 GUIDs
    ```ps1
    $ guidtool -i 95f6e264-bb00-11ec-8833-00155d01ef00
    UUID version: 1
    UUID time: 2022-04-13 08:06:13.202186
    UUID timestamp: 138691299732021860
    UUID node: 91754721024
    UUID MAC address: 00:15:5d:01:ef:00
    UUID clock sequence: 2099
    
    $ guidtool 1b2d78d0-47cf-11ec-8d62-0ff591f2a37c -t '2021-11-17 18:03:17' -p 10000
    ```

### References

* [In GUID We Trust - Daniel Thatcher - October 11, 2022](https://www.intruder.io/research/in-guid-we-trust)