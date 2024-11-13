# CONTRIBUTING

PayloadsAllTheThings' Team :heart: pull requests.

Feel free to improve with your payloads and techniques !

You can also contribute with a :beers: IRL, or using the [sponsor](https://github.com/sponsors/swisskyrepo) button.

## Pull Requests Guidelines

In order to provide the safest payloads for the community, the following rules must be followed for **every** Pull Request.

- Payloads must be sanitized
    - Use `id`, and `whoami`, for RCE Proof of Concepts
    - Use `[REDACTED]` when the user has to replace a domain for a callback. E.g: XSSHunter, BurpCollaborator etc.
    - Use `10.10.10.10` and `10.10.10.11` when the payload require IP addresses
    - Use `Administrator` for privileged users and `User` for normal account
    - Use `P@ssw0rd`, `Password123`, `password` as default passwords for your examples
    - Prefer commonly used name for machines such as `DC01`, `EXCHANGE01`, `WORKSTATION01`, etc
- References must have an `author`, a `title`, a `link` and a `date`
    - Use [Wayback Machine](wayback.archive.org) if the reference is not available anymore.
    - The date must be following the format `Month Number, Year`, e.g: `December 25, 2024`
    - References to Github repositories must follow this format: `[author/tool](https://github.com/URL) - Description`

Every pull request will be checked with `markdownlint` to ensure consistent writing and Markdown best practices. You can validate your files locally using the following Docker command:

```ps1
docker run -v $PWD:/workdir davidanson/markdownlint-cli2:v0.15.0 "**/*.md" --config .github/.markdownlint.json --fix
```

## Techniques Folder

Every section should contains the following files, you can use the `_template_vuln` folder to create a new technique folder:

- **README.md**: vulnerability description and how to exploit it, including several payloads, more below
- **Intruder**: a set of files to give to Burp Intruder
- **Images**: pictures for the README.md
- **Files**: some files referenced in the README.md

## README.md Format

Use the example folder [_template_vuln/](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/_template_vuln/) to create a new vulnerability document. The main page is [README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/_template_vuln/README.md). It is organized with sections for a title and description of the vulnerability, along with a summary table of contents linking to the main sections of the document.

- **Tools**: Lists relevant tools with links to their repositories and brief descriptions.
- **Methodology**: Provides a quick overview of the approach used, with code snippets to demonstrate exploitation steps.
- **Labs**: References online platforms where similar vulnerabilities can be practiced, each with a link to the corresponding lab.
- **References**: Lists external resources, such as blog posts or articles, providing additional context or case studies related to the vulnerability.
