# Bug Hunting Methodology and Enumeration

## Summary

* [Passive Recon](#passive-recon)
  * Shodan
  * Wayback Machine
  * The Harvester
  * Github OSINT

* [Active Recon](#active-recon)
  * [Network discovery](#network-discovery)
  * [Web discovery](#web-discovery)

* [Web Vulnerabilities](#looking-for-web-vulnerabilities)

## Passive recon

* Using [Shodan](https://www.shodan.io/) to detect similar app

  ```bash
  can be integrated with nmap (https://github.com/glennzw/shodan-hq-nse)
  nmap --script shodan-hq.nse --script-args 'apikey=<yourShodanAPIKey>,target=<hackme>'
  ```

* Using [The Wayback Machine](https://archive.org/web/) to detect forgotten endpoints

  ```bash
  look for JS files, old links
  curl -sX GET "http://web.archive.org/cdx/search/cdx?url=<targetDomain.com>&output=text&fl=original&collapse=urlkey&matchType=prefix"
  ```

* Using [The Harvester](https://github.com/laramies/theHarvester)

  ```python
  python theHarvester.py -b all -d domain.com
  ```

* Look for private information in [GitHub]() repos with [GitRob](https://github.com/michenriksen/gitrob.git)
  ```bash
  gitrob analyze johndoe --site=https://github.acme.com --endpoint=https://github.acme.com/api/v3 --access-tokens=token1,token2
  ```

* Perform Google Dorks search


## Active recon

### Network discovery

* Subdomains enumeration
  * Enumerate already found subdomains: [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder): `subfinder -d hackerone.com`
  * Permutate subdomains: [infosec-au/altdns](https://github.com/infosec-au/altdns)
  * Bruteforce subdomains: [Josue87/gotator](https://github.com/Josue87/gotator)
  * Subdomain takeovers: [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)

* Network discovery
  * Scan IP ranges with `nmap`, [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) and [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu)
  * Discover services, version and banners

* Review latest acquisitions

* ASN enumeration
  * [projectdiscovery/asnmap](https://github.com/projectdiscovery/asnmap): `asnmap -a AS45596 -silent`

* DNS Zone Transfer
  ```ps1
  host -t ns domain.local
  domain.local name server master.domain.local.

  host master.domain.local        
  master.domain.local has address 192.168.1.1
 
  dig axfr domain.local @192.168.1.1
  ```

### Web discovery

* Locate `robots.txt`, `security.txt`, `sitemap.xml` files
* Retrieve comments in source code
* Discover URL: [tomnomnom/waybackurls](github.com/tomnomnom/waybackurls)
* Search for `hidden` parameters: [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner)

* List all the subdirectories and files with `gobuster` or `ffuf`
  ```ps1
  # gobuster -w wordlist -u URL -t threads
  ./gobuster -u http://example.com/ -w words.txt -t 10
  ```

* Find backup files with [mazen160/bfac](https://github.com/mazen160/bfac)
  ```bash
  bfac --url http://example.com/test.php --level 4
  bfac --list testing_list.txt
  ```

* Map technologies: Web service enumeration using [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) or Wappalyzer
  * Gather favicon hash, JARM fingerprint, ASN, status code, services and technologies (Github Pages, Cloudflare, Ruby, Nginx,...)

* Take screenshots for every websites using [sensepost/gowitness](https://github.com/sensepost/gowitness)

* Automated vulnerability scanners
  * [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei): `nuclei -u https://example.com`
  * [Burp Suite's web vulnerability scanner](https://portswigger.net/burp/vulnerability-scanner)
  * [sullo/nikto](https://github.com/sullo/nikto): `./nikto.pl -h http://www.example.com`

* Manual Testing: Explore the website with a proxy:
  * [Caido - A lightweight web security auditing toolkit](https://caido.io/)
  * [ZAP - OWASP Zed Attack Proxy](https://www.zaproxy.org/)
  * [Burp Suite - Community Edition](https://portswigger.net/burp/communitydownload)


## Looking for Web vulnerabilities

* Explore the website and look for vulnerabilities listed in this repository: SQL injection, XSS, CRLF, Cookies, ....
* Test for Business Logic weaknesses
  * High or negative numerical values
  * Try all the features and click all the buttons
* [The Web Application Hacker's Handbook Checklist](https://gist.github.com/gbedoya/10935137) copied from http://mdsec.net/wahh/tasks.html

* Subscribe to the site and pay for the additional functionality to test

* Inspect Payment functionality - [@gwendallecoguic](https://twitter.com/gwendallecoguic/status/988138794686779392)
  > if the webapp you're testing uses an external payment gateway, check the doc to find the test credit numbers, purchase something and if the webapp didn't disable the test mode, it will be free

  From https://stripe.com/docs/testing#cards : "Use any of the following test card numbers, a valid expiration date in the future, and any random CVC number, to create a successful payment. Each test card's billing country is set to U.S. "
  e.g :

  Test card numbers and tokens  

  | NUMBER           | BRAND          | TOKEN          |
  | :-------------   | :------------- | :------------- |
  | 4242424242424242 | Visa           | tok_visa       |
  | 4000056655665556 | Visa (debit)   | tok_visa_debit |
  | 5555555555554444 | Mastercard     | tok_mastercard |

  International test card numbers and tokens     

  | NUMBER           | TOKEN          | COUNTRY        | BRAND          |
  | :-------------   | :------------- | :------------- | :------------- |
  | 4000000400000008 | tok_at         | Austria (AT)   | Visa           |
  | 4000000560000004 | tok_be         | Belgium (BE)   | Visa           |
  | 4000002080000001 | tok_dk         | Denmark (DK)   | Visa           |
  | 4000002460000001 | tok_fi         | Finland (FI)   | Visa           |
  | 4000002500000003 | tok_fr         | France (FR)    | Visa           |

## References

* [[BugBounty] Yahoo phpinfo.php disclosure - Patrik Fehrenbach](http://blog.it-securityguard.com/bugbounty-yahoo-phpinfo-php-disclosure-2/)
* [Nmap CheatSheet - HackerTarget](https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/)
