# Methodology and Enumeration

## Bug Hunting Methodology
* Enumerate all subdomains (only if the scope is *.domain.ext)

Using KnockPy with Daniel Miessler’s SecLists for subdomain "/Discover/DNS"
```
git clone https://github.com/guelfoweb/knock
git clone https://github.com/danielmiessler/SecLists.git

knockpy domain.com -w /PATH_TO_SECLISTS/Discover/DNS/subdomains-top1mil-110000.txt
```

Using Jason Haddix's enumall Recon-ng script, 
```
git clone https://LaNMaSteR53@bitbucket.org/LaNMaSteR53/recon-ng.git
cd recon-ng
pip install -r REQUIREMENTS
ln -s /$recon-ng_path /usr/share/recon-ng
git clone https://github.com/jhaddix/domain.git
cd domain
./setup_enumall.sh

./enumall.py domain.com
-w to run a custom wordlist with recon-ng
-a to use alt-dns
-p to feed a custom permutations list to alt-dns (requires -a flag)
-i to feed a list of domains (can also type extra domains into the original command)
```

* Subdomain take over using HostileSubBruteForcer 
```
git clone https://github.com/nahamsec/HostileSubBruteforcer
chmox +x sub_brute.rb
./sub_brute.rb
```

* EyeWitness and Nmap scans from the KnockPy and enumall scans
```
git clone https://github.com/ChrisTruncer/EyeWitness.git
./setup/setup.sh
./EyeWitness.py -f filename -t optionaltimeout --open (Optional)
./EyeWitness -f urls.txt --web
./EyeWitness -x urls.xml -t 8 --headless
./EyeWitness -f rdp.txt --rdp
```

* Basic NMAP (if allowed ^^')
```
sudo nmap -sSV -p- 192.168.0.1 -oA OUTPUTFILE -T4 
sudo nmap -sSV -oA OUTPUTFILE -T4 -iL INPUTFILE.csv

• the flag -sSV defines the type of packet to send to the server and tells Nmap to try and determine any service on open ports
• the -p- tells Nmap to check all 65,535 ports (by default it will only check the most popular 1,000)
• 192.168.0.1 is the IP address to scan
• -oA OUTPUTFILE tells Nmap to output the findings in its three major formats at once using the filename "OUTPUTFILE"
• -iL INPUTFILE tells Nmap to use the provided file as inputs
• -T4 defines the timing for the task (options are 0-5 and higher is faster)
```

* List all the subdirectories with DirBuster or GoBuster
```
./gobuster -u http://buffered.io/ -w words.txt -t 10
-u url
-w wordlist
-t threads

More subdomain :
./gobuster -m dns -w subdomains.txt -u google.com -i
```

* Explore the website
```
 - Start ZAP proxy, visit the main target site and perform a Forced Browse to discover files and directories
 - Map technologies used with Wappalyzer and Burp Suite (or ZAP) proxy
 - Explore and understand available functionality, noting areas that correspond to vulnerability types
```

* Look for private information in GitHub repos with GitRob
```
git clone https://github.com/michenriksen/gitrob.git
gitrob analyze johndoe --site=https://github.acme.com --endpoint=https://github.acme.com/api/v3 --access-tokens=token1,token2
```

* Subscribe to the site and pay for the additional functionality to test

* Launch a Nikto scan in case you missed something


## Google Dorks

Google Dork to find subdomains
```
site:*.domain.com -www
site:http://domain.com ext:php
site:http://domain.com filetype:pdf
```

## Scripts
Script to detect all phpinfo.php files in a range of IPs (CIDR can be found with a whois)
```
#!/bin/bash
for ipa in 98.13{6..9}.{0..255}.{0..255}; do
wget -t 1 -T 3 http://${ipa}/phpinfo.php; done &
```

Script to detect all .htpasswd files in a range of IPs
```
#!/bin/bash
for ipa in 98.13{6..9}.{0..255}.{0..255}; do
wget -t 1 -T 3 http://${ipa}/.htpasswd; done &
```


## Thanks to
* http://blog.it-securityguard.com/bugbounty-yahoo-phpinfo-php-disclosure-2/