# Server Side Template Injection - ASP.NET

## Summary

- [ASP.NET Razor](#aspnet-razor)
    - [ASP.NET Razor - Basic injection](#aspnet-razor---basic-injection)
    - [ASP.NET Razor - Command execution](#aspnet-razor---command-execution)
- [References](#references)


## ASP.NET Razor

[Official website](https://docs.microsoft.com/en-us/aspnet/web-pages/overview/getting-started/introducing-razor-syntax-c)

> Razor is a markup syntax that lets you embed server-based code (Visual Basic and C#) into web pages.


### ASP.NET Razor - Basic injection

```powershell
@(1+2)
```

### ASP.NET Razor - Command execution

```csharp
@{
  // C# code
}
```


## References

- [Server-Side Template Injection (SSTI) in ASP.NET Razor - Clément Notin - April 15, 2020](https://clement.notin.org/blog/2020/04/15/Server-Side-Template-Injection-(SSTI)-in-ASP.NET-Razor/)