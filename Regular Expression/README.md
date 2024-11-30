# Regular Expression

> Regular Expression Denial of Service (ReDoS) is a type of attack that exploits the fact that certain regular expressions can take an extremely long time to process, causing applications or services to become unresponsive or crash. 


## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Evil Regex](#evil-regex)
    * [Backtrack Limit](#backtrack-limit)
* [References](#references)


## Tools

* [tjenkinson/redos-detector](https://github.com/tjenkinson/redos-detector) - A CLI and library which tests with certainty if a regex pattern is safe from ReDoS attacks. Supported in the browser, Node and Deno.
* [doyensec/regexploit](https://github.com/doyensec/regexploit) - Find regular expressions which are vulnerable to ReDoS (Regular Expression Denial of Service)
* [devina.io/redos-checker](https://devina.io/redos-checker) - Examine regular expressions for potential Denial of Service vulnerabilities


## Methodology

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

These regular expressions can be exploited with `aaaaaaaaaaaaaaaaaaaaaaaa!` (20 'a's followed by a '!').

```ps1
aaaaaaaaaaaaaaaaaaaa! 
```

For this input, the regex engine will try all possible ways to group the `a` characters before realizing that the match ultimately fails because of the `!`. This results in an explosion of backtracking attempts.


### Backtrack Limit

Backtracking in regular expressions occurs when the regex engine tries to match a pattern and encounters a mismatch. The engine then backtracks to the previous matching position and tries an alternative path to find a match. This process can be repeated many times, especially with complex patterns and large input strings.  

**PHP PCRE configuration options**

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

- [Intigriti Challenge 1223 - Hackbook Of A Hacker - December 21, 2023](https://simones-organization-4.gitbook.io/hackbook-of-a-hacker/ctf-writeups/intigriti-challenges/1223)
- [MyBB Admin Panel RCE CVE-2023-41362 - SorceryIE - September 11, 2023](https://blog.sorcery.ie/posts/mybb_acp_rce/)
- [OWASP Validation Regex Repository - OWASP - March 14, 2018](https://wiki.owasp.org/index.php/OWASP_Validation_Regex_Repository)
- [PCRE > Installing/Configuring - PHP Manual - May 3, 2008](https://www.php.net/manual/en/pcre.configuration.php#ini.pcre.recursion-limit)
- [Regular expression Denial of Service - ReDoS - Adar Weidman - December 4, 2019](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)