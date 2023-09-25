# Insecure Randomness

## Summary

* [GUID / UUID](#guid--uuid)
    * [GUID Versions](#guid-versions)
    * [Tools](#tools)
* [Mongo ObjectId](#mongo-objectid)
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

## Mongo ObjectId

Mongo ObjectIds are generated in a predictable manner, the 12-byte ObjectId value consists of: 
* **Timestamp** (4 bytes): Represents the ObjectId’s creation time, measured in seconds since the Unix epoch (January 1, 1970).
* **Machine Identifier** (3 bytes): Identifies the machine on which the ObjectId was generated. Typically derived from the machine's hostname or IP address, making it predictable for documents created on the same machine.
* **Process ID** (2 bytes): Identifies the process that generated the ObjectId. Typically the process ID of the MongoDB server process, making it predictable for documents created by the same process.
* **Counter** (3 bytes): A unique counter value that is incremented for each new ObjectId generated. Initialized to a random value when the process starts, but subsequent values are predictable as they are generated in sequence.

### Tools

* [andresriancho/mongo-objectid-predict](https://github.com/andresriancho/mongo-objectid-predict) - Predict Mongo ObjectIds
    ```ps1
    ./mongo-objectid-predict 5ae9b90a2c144b9def01ec37
    5ae9bac82c144b9def01ec39
    5ae9bacf2c144b9def01ec3a
    5ae9bada2c144b9def01ec3b
    ```

### References

* [In GUID We Trust - Daniel Thatcher - October 11, 2022](https://www.intruder.io/research/in-guid-we-trust)
* [IDOR through MongoDB Object IDs Prediction - Amey Anekar - August 25, 2020](https://techkranti.com/idor-through-mongodb-object-ids-prediction/)