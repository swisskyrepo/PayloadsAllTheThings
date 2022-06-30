# CONTRIBUTING

PayloadsAllTheThings' Team :heart: pull requests :)
Feel free to improve with your payloads and techniques !

You can also contribute with a :beers: IRL, or using the sponsor button.

## Pull Requests Guidelines

In order to provide the safest payloads for the community, the following rules must be followed for **every** Pull Request.

- Payloads must be sanitized
  - Use `id`, and `whoami`, for RCE Proof of Concepts
  - Use `[REDACTED]` when the user has to replace a domain for a callback. E.g: XSSHunter, BurpCollaborator etc.
  - Use `10.10.10.10` and `10.10.10.11` when the payload require IP addresses
  - Use `Administrator` for privileged users and `User` for normal account
  - Use `P@ssw0rd`, `Password123`, `password` as default passwords for your examples
  - Prefer commonly used name for machines such as `DC01`, `EXCHANGE01`, `WORKSTATION01`, etc
- References must have an `author`, a `title` and a `link`. The `date` is not mandatory but appreciated :)

## Techniques Folder

Every section should contains the following files, you can use the `_template_vuln` folder to create a new technique folder:

- README.md - vulnerability description and how to exploit it, including several payloads, more below
- Intruder - a set of files to give to Burp Intruder
- Images - pictures for the README.md
- Files - some files referenced in the README.md

## README.md format

Use the following example to create a new technique `README.md` file.

```markdown
# Vulnerability Title

> Vulnerability description

## Summary

* [Tools](#tools)
* [Something](#something)
  * [Subentry 1](#sub1)
  * [Subentry 2](#sub2)
* [References](#references)

## Tools

- [Tool 1](https://example.com)
- [Tool 2](https://example.com)

## Something

Quick explanation

### Subentry 1

Something about the subentry 1

## References

- [Blog title - Author, Date](https://example.com)
```
