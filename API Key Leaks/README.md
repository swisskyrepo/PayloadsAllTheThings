# API Key and Token Leaks

> API keys and tokens are forms of authentication commonly used to manage permissions and access to both public and private services. Leaking these sensitive pieces of data can lead to unauthorized access, compromised security, and potential data breaches.

## Summary

- [Tools](#tools)
- [Methodology](#exploit)
    - [Common Causes of Leaks](#common-causes-of-leaks)
    - [Validate The API Key](#validate-the-api-key)
- [References](#references)


## Tools

- [aquasecurity/trivy](https://github.com/aquasecurity/trivy) - General purpose vulnerability and misconfiguration scanner which also searches for API keys/secrets
- [blacklanternsecurity/badsecrets](https://github.com/blacklanternsecurity/badsecrets) - A library for detecting known or weak secrets on across many platforms
- [d0ge/sign-saboteur](https://github.com/d0ge/sign-saboteur) - SignSaboteur is a Burp Suite extension for editing, signing, verifying various signed web tokens
- [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) - Secrets Patterns DB: The largest open-source Database for detecting secrets, API keys, passwords, tokens, and more.
- [momenbasel/KeyFinder](https://github.com/momenbasel/KeyFinder) - is a tool that let you find keys while surfing the web
- [streaak/keyhacks](https://github.com/streaak/keyhacks) - is a repository which shows quick ways in which API keys leaked by a bug bounty program can be checked to see if they're valid
- [trufflesecurity/truffleHog](https://github.com/trufflesecurity/truffleHog) - Find credentials all over the place
- [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) - Use these templates to test an API token against many API service endpoints
    ```powershell
    nuclei -t token-spray/ -var token=token_list.txt
    ```


## Methodology

* **API Keys**: Unique identifiers used to authenticate requests associated with your project or application.
* **Tokens**: Security tokens (like OAuth tokens) that grant access to protected resources.
     
### Common Causes of Leaks

* **Hardcoding in Source Code**: Developers may unintentionally leave API keys or tokens directly in the source code.

    ```py     
    # Example of hardcoded API key
    api_key = "1234567890abcdef"
    ```

* **Public Repositories**: Accidentally committing sensitive keys and tokens to publicly accessible version control systems like GitHub.

    ```ps1
    ## Scan a Github Organization
    docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
    
    ## Scan a GitHub Repository, its Issues and Pull Requests
    docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys --issue-comments --pr-comments
    ```

* **Hardcoding in Docker Images**: API keys and credentials might be hardcoded in Docker images hosted on DockerHub or private registries.

    ```ps1
    # Scan a Docker image for verified secrets
    docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest docker --image trufflesecurity/secrets
    ```

* **Logs and Debug Information**: Keys and tokens might be inadvertently logged or printed during debugging processes.

* **Configuration Files**: Including keys and tokens in publicly accessible configuration files (e.g., .env files, config.json, settings.py, or .aws/credentials.).


### Validate The API Key

If assistance is needed in identifying the service that generated the token, [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) can be consulted. It is the largest open-source database for detecting secrets, API keys, passwords, tokens, and more. This database contains regex patterns for various secrets.

```yaml
patterns:
  - pattern:
      name: AWS API Gateway
      regex: '[0-9a-z]+.execute-api.[0-9a-z._-]+.amazonaws.com'
      confidence: low
  - pattern:
      name: AWS API Key
      regex: AKIA[0-9A-Z]{16}
      confidence: high
```

Use [streaak/keyhacks](https://github.com/streaak/keyhacks) or read the documentation of the service to find a quick way to verify the validity of an API key.

* **Example**: Telegram Bot API Token

    ```ps1
    curl https://api.telegram.org/bot<TOKEN>/getMe
    ```


## References

* [Finding Hidden API Keys & How to Use Them - Sumit Jain - August 24, 2019](https://web.archive.org/web/20191012175520/https://medium.com/@sumitcfe/finding-hidden-api-keys-how-to-use-them-11b1e5d0f01d)
* [Introducing SignSaboteur: Forge Signed Web Tokens with Ease - Zakhar Fedotkin - May 22, 2024](https://portswigger.net/research/introducing-signsaboteur-forge-signed-web-tokens-with-ease)
* [Private API Key Leakage Due to Lack of Access Control - yox - August 8, 2018](https://hackerone.com/reports/376060)
* [Saying Goodbye to My Favorite 5 Minute P1 - Allyson O'Malley - January 6, 2020](https://www.allysonomalley.com/2020/01/06/saying-goodbye-to-my-favorite-5-minute-p1/)