# DNS Rebinding

> DNS rebinding changes the IP address of an attacker controlled machine name to the IP address of a target application, bypassing the [same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) and thus allowing the browser to make arbitrary requests to the target application and read their responses.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
* [Protection Bypasses](#protection-bypasses)
    * [0.0.0.0](#0000)
    * [CNAME](#CNAME)
    * [localhost](#localhost)
* [References](#references)


## Tools

- [nccgroup/singularity](https://github.com/nccgroup/singularity) - A DNS rebinding attack framework. 
- [rebind.it](http://rebind.it/) - Singularity of Origin Web Client.
- [taviso/rbndr](https://github.com/taviso/rbndr) - Simple DNS Rebinding Service
- [taviso/rebinder](https://lock.cmpxchg8b.com/rebinder.html) - rbndr Tool Helper


## Methodology

**Setup Phase**:

* Register a malicious domain (e.g., `malicious.com`).
* Configure a custom DNS server capable of resolving `malicious.com` to different IP addresses.

**Initial Victim Interaction**:

* Create a webpage on `malicious.com` containing malicious JavaScript or another exploit mechanism.
* Entice the victim to visit the malicious webpage (e.g., via phishing, social engineering, or advertisements).

**Initial DNS Resolution**:

* When the victim's browser accesses `malicious.com`, it queries the attacker's DNS server for the IP address.
* The DNS server resolves `malicious.com` to an initial, legitimate-looking IP address (e.g., 203.0.113.1).

**Rebinding to Internal IP**:

* After the browser's initial request, the attacker's DNS server updates the resolution for `malicious.com` to a private or internal IP address (e.g., 192.168.1.1, corresponding to the victim’s router or other internal devices).

This is often achieved by setting a very short TTL (time-to-live) for the initial DNS response, forcing the browser to re-resolve the domain.

**Same-Origin Exploitation:**

The browser treats subsequent responses as coming from the same origin (`malicious.com`).

Malicious JavaScript running in the victim's browser can now make requests to internal IP addresses or local services (e.g., 192.168.1.1 or 127.0.0.1), bypassing same-origin policy restrictions.


**Example:**

1. Register a domain.
2. [Setup Singularity of Origin](https://github.com/nccgroup/singularity/wiki/Setup-and-Installation).
3. Edit the [autoattack HTML page](https://github.com/nccgroup/singularity/blob/master/html/autoattack.html) for your needs.
4. Browse to "http://rebinder.your.domain:8080/autoattack.html".
5. Wait for the attack to finish (it can take few seconds/minutes).


## Protection Bypasses

> Most DNS protections are implemented in the form of blocking DNS responses containing unwanted IP addresses at the perimeter, when DNS responses enter the internal network. The most common form of protection is to block private IP addresses as defined in RFC 1918 (i.e. 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Some tools allow to additionally block localhost (127.0.0.0/8), local (internal) networks, or 0.0.0.0/0 network ranges.

In the case where DNS protection are enabled (generally disabled by default), NCC Group has documented multiple [DNS protection bypasses](https://github.com/nccgroup/singularity/wiki/Protection-Bypasses) that can be used.

### 0.0.0.0

We can use the IP address 0.0.0.0 to access the localhost (127.0.0.1) to bypass filters blocking DNS responses containing 127.0.0.1 or 127.0.0.0/8.

### CNAME

We can use DNS CNAME records to bypass a DNS protection solution that blocks all internal IP addresses.
Since our response will only return a CNAME of an internal server,
the rule filtering internal IP addresses will not be applied.
Then, the local, internal DNS server will resolve the CNAME.

```bash
$ dig cname.example.com +noall +answer
; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer
;; global options: +cmd
cname.example.com.            381     IN      CNAME   target.local.
```

### localhost

We can use "localhost" as a DNS CNAME record to bypass filters blocking DNS responses containing 127.0.0.1.

```bash
$ dig www.example.com +noall +answer
; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer
;; global options: +cmd
localhost.example.com.            381     IN      CNAME   localhost.
```


## References

- [How Do DNS Rebinding Attacks Work? - nccgroup - Apr 9, 2019](https://github.com/nccgroup/singularity/wiki/How-Do-DNS-Rebinding-Attacks-Work%3F)
