# Dependency Confusion

> A dependency confusion attack or supply chain substitution attack occurs when a software installer script is tricked into pulling a malicious code file from a public repository instead of the intended file of the same name from an internal repository.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [NPM Example](#npm-example)
* [References](#references)


## Tools

* [visma-prodsec/confused](https://github.com/visma-prodsec/confused) - Tool to check for dependency confusion vulnerabilities in multiple package management systems
* [synacktiv/DepFuzzer](https://github.com/synacktiv/DepFuzzer) - Tool used to find dependency confusion or project where owner's email can be takeover.


## Methodology

Look for `npm`, `pip`, `gem` packages, the methodology is the same : you register a public package with the same name of private one used by the company and then you wait for it to be used.

* DockerHub: Dockerfile image
* JavaScript (npm): package.json
* MVN (maven): pom.xml
* PHP (composer): composer.json
* Python (pypi): requirements.txt

### NPM Example

* List all the packages (ie: package.json, composer.json, ...)
* Find the package missing from https://www.npmjs.com/
* Register and create a **public** package with the same name
    * Package example : https://github.com/0xsapra/dependency-confusion-expoit


## References

- [Exploiting Dependency Confusion - Aman Sapra (0xsapra) - 2 Jul 2021](https://0xsapra.github.io/website//Exploiting-Dependency-Confusion)
- [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies - Alex Birsan - 9 Feb 2021](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [3 Ways to Mitigate Risk When Using Private Package Feeds - Microsoft - 29/03/2021](https://web.archive.org/web/20210210121930/https://azure.microsoft.com/en-gb/resources/3-ways-to-mitigate-risk-using-private-package-feeds/)
- [$130,000+ Learn New Hacking Technique in 2021 - Dependency Confusion - Bug Bounty Reports Explained - 22 févr. 2021](https://www.youtube.com/watch?v=zFHJwehpBrU)