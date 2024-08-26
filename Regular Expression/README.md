# Regular Expression

> Regular Expression Denial of Service (ReDoS) is a type of attack that exploits the fact that certain regular expressions can take an extremely long time to process, causing applications or services to become unresponsive or crash. 


## Denial of Service - ReDoS

* [tjenkinson/redos-detector](https://github.com/tjenkinson/redos-detector) - A CLI and library which tests with certainty if a regex pattern is safe from ReDoS attacks. Supported in the browser, Node and Deno.
* [doyensec/regexploit](https://github.com/doyensec/regexploit) - Find regular expressions which are vulnerable to ReDoS (Regular Expression Denial of Service)
* [devina.io/redos-checker](https://devina.io/redos-checker) - Examine regular expressions for potential Denial of Service vulnerabilities


### Evil Regex

Evil Regex contains:

* Grouping with repetition
* Inside the repeated group:
    * Repetition
    * Alternation with overlapping

**Examples**

* `(a+)+`
* `([a-zA-Z]+)*`
* `(a|aa)+`
* `(a|a?)+`
* `(.*a){x}` for x \> 10

These regular expressions can be exploited with `aaaaaaaaaaaaaaaaaaaaaaaa!`


### Backtrack Limit

Backtracking in regular expressions occurs when the regex engine tries to match a pattern and encounters a mismatch. The engine then backtracks to the previous matching position and tries an alternative path to find a match. This process can be repeated many times, especially with complex patterns and large input strings.  

PHP PCRE configuration options

| Name                 | Default | Note |
|----------------------|---------|---------|
| pcre.backtrack_limit | 1000000 | 100000 for `PHP < 5.3.7`|
| pcre.recursion_limit | 100000  | / |
| pcre.jit             | 1       | / |


Sometimes it is possible to force the regex to exceed more than 100 000 recursions which will cause a ReDOS and make `preg_match` returning false:

```php
$pattern = '/(a+)+$/';
$subject = str_repeat('a', 1000) . 'b';

if (preg_match($pattern, $subject)) {
    echo "Match found";
} else {
    echo "No match";
}
```


## References

* [Regular expression Denial of Service - ReDoS - OWASP - Adar Weidman](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
* [OWASP Validation Regex Repository - OWASP](https://wiki.owasp.org/index.php/OWASP_Validation_Regex_Repository)
* [PHP Manual > Function Reference > Text Processing > PCRE > Installing/Configuring > Runtime Configuration](https://www.php.net/manual/en/pcre.configuration.php#ini.pcre.recursion-limit)
* [Intigriti Challenge 1223 - HACKBOOK OF A HACKER](https://simones-organization-4.gitbook.io/hackbook-of-a-hacker/ctf-writeups/intigriti-challenges/1223)
* [MyBB Admin Panel RCE CVE-2023-41362 - SorceryIE - 2023-09-11](https://blog.sorcery.ie/posts/mybb_acp_rce/)