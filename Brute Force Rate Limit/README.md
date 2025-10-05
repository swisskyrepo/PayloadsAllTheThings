# Brute Force & Rate Limit

## Summary

* [Tools](#tools)
* [Bruteforce](#bruteforce)
    * [Burp Suite Intruder](#burp-suite-intruder)
    * [FFUF](#ffuf)
* [Rate Limit](#rate-limit)
    * [TLS Stack - JA3](#tls-stack---ja3)
    * [Network IPv4](#network-ipv4)
    * [Network IPv6](#network-ipv6)
* [References](#references)

## Tools

* [ddd/gpb](https://github.com/ddd/gpb) - Bruteforcing the phone number of any Google user while rotating IPv6 addresses.
* [ffuf/ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer written in Go.
* [PortSwigger/Burp Suite](https://portswigger.net/burp) - The class-leading vulnerability scanning, penetration testing, and web app security platform.
* [lwthiker/curl-impersonate](https://github.com/lwthiker/curl-impersonate) - A special build of curl that can impersonate Chrome & Firefox.

## Bruteforce

In a web context, brute-forcing refers to the method of attempting to gain unauthorized access to web applications, particularly through login forms or other user input fields. Attackers systematically input numerous combinations of credentials or other values (e.g., iterating through numeric ranges) to exploit weak passwords or inadequate security measures.

For instance, they might submit thousands of username and password combinations or guess security tokens by iterating through a range, such as 0 to 10,000. This method can lead to unauthorized access and data breaches if not mitigated effectively.

Countermeasures like rate limiting, account lockout policies, CAPTCHA, and strong password requirements are essential to protect web applications from such brute-force attacks.

### Burp Suite Intruder

* **Sniper attack**: target a single position (one variable) while cycling through one payload set.

    ```ps1

    Username: password
    Username1:Password1
    Username1:Password2
    Username1:Password3
    Username1:Password4
    ```

* **Battering ram attack**: send the same payload to all marked positions at once by using a single payload set.

    ```ps1
    Username1:Username1
    Username2:Username2
    Username3:Username3
    Username4:Username4
    ```

* **Pitchfork attack**: use different payload lists in parallel, combining the nth entry from each list into one request.

    ```ps1
    Username1:Password1
    Username2:Password2
    Username3:Password3
    Username4:Password4
    ```

* **Cluster bomb attack**: iterate through all combinations of multiple payload sets.

    ```ps1
    Username1:Password1
    Username1:Password2
    Username1:Password3
    Username1::Password4

    Username2:Password1
    Username2:Password2
    Username2:Password3
    Username2:Password4
    ```

### FFUF

```bash
ffuf -w usernames.txt:USER -w passwords.txt:PASS \
     -u https://target.tld/login \
     -X POST -d "username=USER&password=PASS" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "X-Forwarded-For: FUZZ" -w ipv4-list.txt:FUZZ \
     -mc all
```

## Rate Limit

### HTTP Pipelining

HTTP pipelining is a feature of HTTP/1.1 that lets a client send multiple HTTP requests on a single persistent TCP connection without waiting for the corresponding responses first. The client "pipes" requests one after another over the same connection.

### TLS Stack - JA3

JA3 is a method for fingerprinting TLS clients (and JA3S for TLS servers) by hashing the contents of the TLS "hello" messages. It gives a compact identifier you can use to detect, classify, and track clients on the network even when higher-level protocol fields (like HTTP user-agent) are hidden or faked.

> JA3 gathers the decimal values of the bytes for the following fields in the Client Hello packet; SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats. It then concatenates those values together in order, using a "," to delimit each field and a "-" to delimit each value in each field.

* Burp Suite JA3: `53d67b2a806147a7d1d5df74b54dd049`, `62f6a6727fda5a1104d5b147cd82e520`
* Tor Client JA3: `e7d705a3286e19ea42f587b344ee6865`

**Countermeasures:**

* Use browser-driven automation (Puppeteer / Playwright)
* Spoof TLS handshakes with [lwthiker/curl-impersonate](https://github.com/lwthiker/curl-impersonate)
* JA3 randomization plugins for browsers/libraries

### Network IPv4

Use multiple proxies to simulate multiple clients.

```bash
proxychains ffuf -w wordlist.txt -u https://target.tld/FUZZ
```

* Use `random_chain` to rotate each request

    ```ps1
    random_chain
    ```

* Set the number of proxies to chain per connection to 1.

    ```ps1
    chain_len = 1
    ```

* Finally, specify the proxies in a configuration file:

    ```ps1
    # type  host      port
    socks5  127.0.0.1 1080
    socks5  192.168.1.50 1080
    http    proxy1.example.com 8080
    http    proxy2.example.com 8080
    ```

### Network IPv6

Many cloud providers, such as Vultr, offer /64 IPv6 ranges, which provide a vast number of addresses (18 446 744 073 709 551 616). This allows for extensive IP rotation during brute-force attacks.

## References

* [Bruteforcing the phone number of any Google user - brutecat - June 9, 2025](https://brutecat.com/articles/leaking-google-phones)
* [Burp Intruder attack types - PortSwigger - August 19, 2025](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/attack-types)
* [Detecting and annoying Burp users - Julien Voisin -  May 3, 2021](https://dustri.org/b/detecting-and-annoying-burp-users.html)
