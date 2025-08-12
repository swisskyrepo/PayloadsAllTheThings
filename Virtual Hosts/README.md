# Virtual Host

> A **Virtual Host** (VHOST) is a mechanism used by web servers (e.g., Apache, Nginx, IIS) to host multiple domains or subdomains on a single IP address. When enumerating a webserver, default requests often target the primary or default VHOST only. **Hidden hosts** may expose extra functionality or vulnerabilities.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
* [References](#references)

## Tools

* [wdahlenburg/VhostFinder](https://github.com/wdahlenburg/VhostFinder) - Identify virtual hosts by similarity comparison.
* [codingo/VHostScan](https://github.com/codingo/VHostScan) - A virtual host scanner that can be used with pivot tools, detect catch-all scenarios, aliases and dynamic default pages.
* [hakluke/hakoriginfinder](https://github.com/hakluke/hakoriginfinder) - Tool for discovering the origin host behind a reverse proxy. Useful for bypassing cloud WAFs.

    ```ps1
    prips 93.184.216.0/24 | hakoriginfinder -h https://example.com:443/foo
    ```

* [OJ/gobuster](https://github.com/OJ/gobuster) - Directory/File, DNS and VHost busting tool written in Go.

    ```ps1
    gobuster vhost -u https://example.com -w /path/to/wordlist.txt
    ```

## Methodology

When a web server hosts multiple websites on the same IP address, it uses **Virtual Hosting** to decide which site to serve when a request comes in.

In HTTP/1.1 and above, every request must contain a `Host` header:

```http
GET / HTTP/1.1
Host: example.com
```

This header tells the server which domain the client is trying to reach.

* If the server only has one site: The `Host` header is often ignored or set to a default.
* If the server has multiple virtual hosts: The web server uses the `Host` header to route the request internally to the right content.

Suppose the server is configured like:

```ps1
<VirtualHost *:80>
    ServerName site-a.com
    DocumentRoot /var/www/a
</VirtualHost>

<VirtualHost *:80>
    ServerName site-b.com
    DocumentRoot /var/www/b
</VirtualHost>
```

A request with the default host ("site-a.com") returns the content for Site A.

```http
GET / HTTP/1.1
Host: site-a.com
```

A request with an altered host ("site-b.com") returns content for Site B (possibly revealing something new).

```http
GET / HTTP/1.1
Host: site-b.com
```

### Fingerprinting VHOSTs

Setting `Host` to other known or guessed domains may give **different responses**.

```ps1
curl -H "Host: admin.example.com" http://10.10.10.10/
```

Common indicators that you're hitting a different VHOST:

* Different HTML titles, meta descriptions, or brand names
* Different HTTP Content-Length / body size
* Different status codes (200 vs. 403 or redirect)
* Custom error pages
* Redirect chains to completely different domains
* Certificates with Subject Alternative Names listing other domains

**NOTE**: Leverage DNS history records to identify old IP addresses previously associated with your target’s domains. Then test (or "spray") the current domain names against those IPs. If successful, this can reveal the server’s real address, allowing you to bypass protections like Cloudflare or other WAFs by interacting directly with the origin server.

## References

* [Gobuster for directory, DNS and virtual hosts bruteforcing - erev0s - March 17, 2020](https://erev0s.com/blog/gobuster-directory-dns-and-virtual-hosts-bruteforcing/)
* [Virtual Hosting – A Well Forgotten Enumeration Technique - Wyatt Dahlenburg - June 16, 2022](https://wya.pl/2022/06/16/virtual-hosting-a-well-forgotten-enumeration-technique/)
