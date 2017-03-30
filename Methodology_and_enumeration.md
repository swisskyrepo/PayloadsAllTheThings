# Bug Hunting Methodology and Enumeration

## Enumerate all subdomains (only if the scope is *.domain.ext)

* Using Subbrute
```bash
git clone https://github.com/TheRook/subbrute

python subbrute.py domain.example.com
```

* Using KnockPy with Daniel Miessler’s SecLists for subdomain "/Discover/DNS"
```bash
git clone https://github.com/guelfoweb/knock
git clone https://github.com/danielmiessler/SecLists.git

knockpy domain.com -w /PATH_TO_SECLISTS/Discover/DNS/subdomains-top1mil-110000.txt
```

* Using Google Dorks
```bash
site:*.domain.com -www
site:http://domain.com ext:php
site:http://domain.com filetype:pdf
```

* Using Jason Haddix's enumall Recon-ng script, 
```bash
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
```bash
git clone https://github.com/nahamsec/HostileSubBruteforcer
chmox +x sub_brute.rb
./sub_brute.rb
```

* EyeWitness and Nmap scans from the KnockPy and enumall scans
```bash
git clone https://github.com/ChrisTruncer/EyeWitness.git
./setup/setup.sh
./EyeWitness.py -f filename -t optionaltimeout --open (Optional)
./EyeWitness -f urls.txt --web
./EyeWitness -x urls.xml -t 8 --headless
./EyeWitness -f rdp.txt --rdp
```

## Passive recon
```
Using Shodan (https://www.shodan.io/) to detect similar app
Using The Wayback Machine (https://archive.org/web/) to detect forgotten endpoint
Using The Harvester (https://github.com/laramies/theHarvester) 
```


## Active recon
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

* NMAP Script
```
nmap --script 'http-enum' -v web.xxxx.com -p80 -oN http-enum.nmap
PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /phpmyadmin/: phpMyAdmin
|   /.git/HEAD: Git folder
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|_  /image/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'

List Nmap scripts : ls /usr/share/nmap/scripts/
```

## List all the subdirectories and files 
* Using DirBuster or GoBuster
```bash
./gobuster -u http://buffered.io/ -w words.txt -t 10
-u url
-w wordlist
-t threads

More subdomain :
./gobuster -m dns -w subdomains.txt -u google.com -i

gobuster -w wordlist -u URL -r -e
```


* Using a script to detect all phpinfo.php files in a range of IPs (CIDR can be found with a whois)
```bash
#!/bin/bash
for ipa in 98.13{6..9}.{0..255}.{0..255}; do
wget -t 1 -T 3 http://${ipa}/phpinfo.php; done &
```

* Using a script to detect all .htpasswd files in a range of IPs
```bash
#!/bin/bash
for ipa in 98.13{6..9}.{0..255}.{0..255}; do
wget -t 1 -T 3 http://${ipa}/.htpasswd; done &
```

## Looking for Web vulnerabilities

* Look for private information in GitHub repos with GitRob
```
git clone https://github.com/michenriksen/gitrob.git
gitrob analyze johndoe --site=https://github.acme.com --endpoint=https://github.acme.com/api/v3 --access-tokens=token1,token2
```

* Explore the website with a proxy (ZAP/Burp Suite)
 1. Start ZAP proxy, visit the main target site and perform a Forced Browse to discover files and directories
 2. Map technologies used with Wappalyzer and Burp Suite (or ZAP) proxy
 3. Explore and understand available functionality, noting areas that correspond to vulnerability types
```
Burp Proxy configuration on port 8080 (in .bashrc):
alias set_proxy_burp='gsettings set org.gnome.system.proxy.http host "http://localhost";gsettings set org.gnome.system.proxy.http port 8080;gsettings set org.gnome.system.proxy mode "manual"'
then launch Burp with : java -jar burpsuite_free_v*.jar &
```

* Checklist for Web vulns
```
[] AWS Amazon Bucket S3  
[] Git Svn insecure files   
[] CVE Shellshock Heartbleed  
[] Open redirect            
[] Traversal directory    
[] XSS injection
[] CRLF injection  
[] CSRF injection          
[] SQL injection            
[] NoSQL injection                 
[] PHP include      
[] Upload insecure files     
[] SSRF injection         
[] XXE injections
[] CSV injection 
[] PHP serialization   
```

* Subscribe to the site and pay for the additional functionality to test

* Launch a Nikto scan in case you missed something
```
nikto -h 192.168.1.1
```

## Thanks to
* http://blog.it-securityguard.com/bugbounty-yahoo-phpinfo-php-disclosure-2/
