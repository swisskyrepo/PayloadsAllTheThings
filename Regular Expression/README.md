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


## References

* [Regular expression Denial of Service - ReDoS - OWASP - Adar Weidman](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
* [OWASP Validation Regex Repository - OWASP](https://wiki.owasp.org/index.php/OWASP_Validation_Regex_Repository)