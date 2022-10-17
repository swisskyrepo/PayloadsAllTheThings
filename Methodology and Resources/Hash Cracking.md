# Hash Cracking

## Summary

* [Hashcat](https://hashcat.net/hashcat/)
   * [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
   * [Hashcat Install](#hashcat-install)
   * [Mask attack](#mask-attack)
   * [Dictionary](#dictionary)
* [John](https://github.com/openwall/john)
   * [Usage](#john-usage)
* [Rainbow tables](#rainbow-tables)
* [Tips and Tricks](#tips-and-tricks)
* [Online Cracking Resources](#online-cracking-resources)
* [References](#references)


## Hashcat

### Hashcat Install

```powershell
apt install cmake build-essential -y
apt install checkinstall git -y
git clone https://github.com/hashcat/hashcat.git && cd hashcat && make -j 8 && make install
```

1. Extract the hash
2. Get the hash format: https://hashcat.net/wiki/doku.php?id=example_hashes
3. Establish a cracking stratgy based on hash format (ex: wordlist -> wordlist + rules -> mask -> combinator mode -> prince attack -> ...)
4. Enjoy plains
5. Review strategy
6. Start over

### Dictionary

> Every word of a given list (a.k.a. dictionary) is hashed and compared against the target hash.

```powershell
hashcat --attack-mode 0 --hash-type $number $hashes_file $wordlist_file -r $my_rules
```

* Wordlists
    * [packetstorm](https://packetstormsecurity.com/Crackers/wordlists/)
    * [weakpass_3a](https://download.weakpass.com/wordlists/1948/weakpass_3a.7z)
    * [weakpass_3](https://download.weakpass.com/wordlists/1947/weakpass_3.7z)
    * [Hashes.org](https://download.weakpass.com/wordlists/1931/Hashes.org.7z)
    * [kerberoast_pws](https://gist.github.com/edermi/f8b143b11dc020b854178d3809cf91b5/raw/b7d83af6a8bbb43013e04f78328687d19d0cf9a7/kerberoast_pws.xz)
    * [hashmob.net](https://hashmob.net/research/wordlists)
    * [clem9669/wordlists](https://github.com/clem9669/wordlists)

* Rules
    * [One Rule to Rule Them All](https://notsosecure.com/one-rule-to-rule-them-all/)
    * [nsa-rules](https://github.com/NSAKEY/nsa-rules)
    * [hob064](https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/hob064.rule)
    * [d3adhob0](https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/d3adhob0.rule)
    * [clem9669/hashcat-rule](https://github.com/clem9669/hashcat-rule)

### Mask attack

Mask attack is an attack mode which optimize brute-force.

> Every possibility for a given character set and a given length (i.e. aaa, aab, aac, ...) is hashed and compared against the target hash.

```powershell
# Mask: upper*1+lower*5+digit*2 and upper*1+lower*6+digit*2 
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 ?u?l?l?l?l?l?d?d
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 ?u?l?l?l?l?l?l?d?d 
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 -1 "*+!??" ?u?l?l?l?l?l?d?d?1
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 -1 "*+!??" ?u?l?l?l?l?l?l?d?d?1 

# Mask: upper*1+lower*3+digit*4 and upper*1+lower*3+digit*4
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 ?u?l?l?l?d?d?d?d
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 ?u?l?l?l?l?d?d?d?d
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 ?u?l?l?l?l?l?d?d?d?d
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 -1 "*+!??" ?u?l?l?l?d?d?d?d?1
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 -1 "*+!??" ?u?l?l?l?l?d?d?d?d?1

# Mask: lower*6 + digit*2 + special digit(+!?*)
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 -1 "*+!??" ?l?l?l?l?l?l?d?d?1
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 -1 "*+!??" ?l?l?l?l?l?l?d?d?1?1

# Mask: lower*6 + digit*2
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 /content/hashcat/masks/8char-1l-1u-1d-1s-compliant.hcmask
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 -1 ?l?d?u ?1?1?1?1?1?1?1?1

# Other examples
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 ?a?a?a?a?a?a?a?a?a
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 ?a?a?a?a?a?a?a?a 
hashcat -m 1000 --status --status-timer 300 -w 4 -O /content/*.ntds -a 3 ?u?l?l?l?l?l?l?d?d?d?d
hashcat --attack-mode 3 --increment --increment-min 4 --increment-max 8 --hash-type $number $hashes_file "?a?a?a?a?a?a?a?a?a?a?a?a"
hashcat --attack-mode 3 --hash-type $number $hashes_file "?u?l?l?l?d?d?d?d?s"
hashcat --attack-mode 3 --hash-type $number $hashes_file "?a?a?a?a?a?a?a?a"
hashcat --attack-mode 3 --custom-charset1 "?u" --custom-charset2 "?l?u?d" --custom-charset3 "?d" --hash-type $number $hashes_file "?1?2?2?2?3"
```

| Shortcut  | Characters  |
|----|----------------------------|
| ?l | abcdefghijklmnopqrstuvwxyz |
| ?u | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| ?d | 0123456789 |
| ?s | !"#$%&'()*+,-./:;<=>?@[\]^_`{}~ |
| ?a | ?l?u?d?s |
| ?b | 0x00 - 0xff |



## John


### John Usage

```bash
# Run on password file containing hashes to be cracked
john passwd

# Use a specific wordlist
john --wordlist=<wordlist> passwd

# Use a specific wordlist with rules
john --wordlist=<wordlist> passwd --rules=Jumbo

# Show cracked passwords
john --show passwd

# Restore interrupted sessions
john --restore
```


## Rainbow tables

> The hash is looked for in a pre-computed table. It is a time-memory trade-off that allows cracking hashes faster, but costing a greater amount of memory than traditional brute-force of dictionary attacks. This attack cannot work if the hashed value is salted (i.e. hashed with an additional random value as prefix/suffix, making the pre-computed table irrelevant)

## Tips and Tricks

* Cloud GPU
    * [penglab - Abuse of Google Colab for cracking hashes. 🐧](https://github.com/mxrch/penglab)
    * [google-colab-hashcat - Google colab hash cracking](https://github.com/ShutdownRepo/google-colab-hashcat)
    * [Cloudtopolis - Zero Infrastructure Password Cracking](https://github.com/JoelGMSec/Cloudtopolis)
    * [Nephelees - also a NTDS cracking tool abusing Google Colab](https://github.com/swisskyrepo/Nephelees)
* Build a rig on premise
    * [Pentester's Portable Cracking Rig - $1000](https://www.netmux.com/blog/portable-cracking-rig)
    * [How To Build A Password Cracking Rig - 5000$](https://www.netmux.com/blog/how-to-build-a-password-cracking-rig)
* Online cracking
    * [Hashes.com](https://hashes.com/en/decrypt/hash)
    * [hashmob.net](https://hashmob.net/): great community with Discord
* Use the `loopback` in combination with rules and dictionary to keep cracking until you don't find new passsword: `hashcat --loopback --attack-mode 0 --rules-file $rules_file --hash-type $number $hashes_file $wordlist_file`
* PACK (Password Analysis and Cracking Kit)
    * https://github.com/iphelix/pack/blob/master/README
    * Can produce custom hcmask files to use with hashcat, based on statistics and rules applied on an input dataset
* Use Deep Learning
    * [brannondorsey/PassGAN](https://github.com/brannondorsey/PassGAN)


## Online Cracking Resources

* [hashes.com](https://hashes.com)
* [crackstation](https://crackstation.net)
* [Hashmob](https://hashmob.net/)


## References

* [Cracking - The Hacker Recipes](https://www.thehacker.recipes/ad-ds/movement/credentials/cracking)
* [Using Hashcat to Crack Hashes on Azure](https://durdle.com/2017/04/23/using-hashcat-to-crack-hashes-on-azure/)
* [miloserdov.org hashcat](https://miloserdov.org/?p=5426&PageSpeed=noscript)
* [miloserdov.org john](https://miloserdov.org/?p=4961&PageSpeed=noscript)
* [DeepPass — Finding Passwords With Deep Learning - Will Schroeder - Jun 1](https://posts.specterops.io/deeppass-finding-passwords-with-deep-learning-4d31c534cd00)