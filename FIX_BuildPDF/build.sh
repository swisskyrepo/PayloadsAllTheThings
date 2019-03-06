# GitPrint from Payload

find .  -name "*.md" | sed "s/\.\///g" | sort | xargs -I{} wget --content-disposition "https://gitprint.com/swisskyrepo/PayloadsAllTheThings/blob/master/"{}"?download"
pdfjoin *.pdf 


# NOTE : 
# check for 502 errors from gitprint
# XSS and Mimikatz don't work with Gitprint ;.