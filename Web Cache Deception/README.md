# Web Cache Deception

## Summary

* [Tools](#tools)
* [Exploit](#exploit)
    * [Methodology - Caching Sensitive Data](#methodology---caching-sensitive-data)
    * [Methodology - Caching Custom JavaScript](#methodology---caching-custom-javascript)
* [CloudFlare Caching](#cloudflare-caching)
* [Labs](#labs)
* [References](#references)


## Tools

* [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner)
    > This extension identifies hidden, unlinked parameters. It's particularly useful for finding web cache poisoning vulnerabilities.

## Exploit

1. Browser requests a resource such as `http://www.example.com/home.php/non-existent.css`.
2. Server returns the content of `http://www.example.com/home.php`, most probably with HTTP caching headers that instruct to not cache this page.
3. The response goes through the proxy.
4. The proxy identifies that the file has a css extension.
5. Under the cache directory, the proxy creates a directory named home.php, and caches the imposter "CSS" file (non-existent.css) inside.


### Methodology - Caching Sensitive Data

**Example 1** - Web Cache Deception on PayPal Home Page
1. Normal browsing, visit home : `https://www.example.com/myaccount/home/`
2. Open the malicious link : `https://www.example.com/myaccount/home/malicious.css`
3. The page is displayed as /home and the cache is saving the page
4. Open a private tab with the previous URL : `https://www.example.com/myaccount/home/malicous.css`
5. The content of the cache is displayed

Video of the attack by Omer Gil - Web Cache Deception Attack in PayPal Home Page
[![DEMO](https://i.vimeocdn.com/video/674856618.jpg)](https://vimeo.com/249130093)

**Example 2** - Web Cache Deception on OpenAI
1. Attacker crafts a dedicated .css path of the `/api/auth/session` endpoint.
2. Attacker distributes the link
3. Victims visit the legitimate link.
4. Response is cached.
5. Attacker harvests JWT Credentials.


### Methodology - Caching Custom JavaScript

1. Find an un-keyed input for a Cache Poisoning
    ```js
    Values: User-Agent
    Values: Cookie
    Header: X-Forwarded-Host
    Header: X-Host
    Header: X-Forwarded-Server
    Header: X-Forwarded-Scheme (header; also in combination with X-Forwarded-Host)
    Header: X-Original-URL (Symfony)
    Header: X-Rewrite-URL (Symfony)
    ```
2. Cache poisoning attack - Example for `X-Forwarded-Host` un-keyed input (remember to use a buster to only cache this webpage instead of the main page of the website)
    ```js
    GET /test?buster=123 HTTP/1.1
    Host: target.com
    X-Forwarded-Host: test"><script>alert(1)</script>

    HTTP/1.1 200 OK
    Cache-Control: public, no-cache
    [..]
    <meta property="og:image" content="https://test"><script>alert(1)</script>">
    ```


## CloudFlare Caching

CloudFlare caches the resource when the `Cache-Control` header is set to `public` and `max-age` is greater than 0. 

- The Cloudflare CDN does not cache HTML by default
- Cloudflare only caches based on file extension and not by MIME type: [cloudflare/default-cache-behavior](https://developers.cloudflare.com/cache/about/default-cache-behavior/)

CloudFlare has a list of default extensions that gets cached behind their Load Balancers.

|       |      |      |      |      |       |      |
|-------|------|------|------|------|-------|------|
| 7Z    | CSV  | GIF  | MIDI | PNG  | TIF   | ZIP  |
| AVI   | DOC  | GZ   | MKV  | PPT  | TIFF  | ZST  |
| AVIF  | DOCX | ICO  | MP3  | PPTX | TTF   | CSS  |
| APK   | DMG  | ISO  | MP4  | PS   | WEBM  | FLAC |
| BIN   | EJS  | JAR  | OGG  | RAR  | WEBP  | MID  |
| BMP   | EOT  | JPG  | OTF  | SVG  | WOFF  | PLS  |
| BZ2   | EPS  | JPEG | PDF  | SVGZ | WOFF2 | TAR  |
| CLASS | EXE  | JS   | PICT | SWF  | XLS   | XLSX |


## Labs 

* [PortSwigger Labs for Web cache deception](https://portswigger.net/web-security/all-labs#web-cache-poisoning)

## References

* [Web Cache Deception Attack - Omer Gil](http://omergil.blogspot.fr/2017/02/web-cache-deception-attack.html)
* [Practical Web Cache Poisoning - James Kettle @albinowax](https://portswigger.net/blog/practical-web-cache-poisoning)
* [Web Cache Entanglement: Novel Pathways to Poisoning - James Kettle @albinowax](https://portswigger.net/research/web-cache-entanglement)
* [Web Cache Deception Attack leads to user info disclosure - Kunal pandey - Feb 25](https://medium.com/@kunal94/web-cache-deception-attack-leads-to-user-info-disclosure-805318f7bb29)
* [Web cache poisoning - Web Security Academy learning materials](https://portswigger.net/web-security/web-cache-poisoning)
  - [Exploiting cache design flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
  - [Exploiting cache implementation flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws)
* [OpenAI Account Takeover - @naglinagli - Mar 24, 2023](https://twitter.com/naglinagli/status/1639343866313601024)
* [Shockwave Identifies Web Cache Deception and Account Takeover Vulnerability affecting OpenAI's ChatGPT - Gal Nagli](https://www.shockwave.cloud/blog/shockwave-works-with-openai-to-fix-critical-chatgpt-vulnerability)