# Insecure Source Code Management

> Insecure Source Code Management (SCM) can lead to several critical vulnerabilities in web applications and services. Developers often rely on SCM systems like Git and Subversion (SVN) to manage their source code versions. However, poor security practices, such as leaving .git and .svn folders in production environments exposed to the internet, can pose significant risks. 


## Summary

* [Methodology](#methodology)
    * [Bazaar](./Bazaar.md)
    * [Git](./Git.md)
    * [Mercurial](./Mercurial.md)
    * [Subversion](./Subversion.md)
* [Labs](#labs)
* [References](#references)


## Methodology

Exposing the version control system folders on a web server can lead to severe security risks, including: 

- **Source Code Leaks** : Attackers can download the entire source code repository, gaining access to the application's logic.
- **Sensitive Information Exposure** : Embedded secrets, configuration files, and credentials might be present within the codebase.
- **Commit History Exposure** : Attackers can view past changes, revealing sensitive information that might have been previously exposed and later mitigated.
     

The first step is to gather information about the target application. This can be done using various web reconnaissance tools and techniques. 

* **Manual Inspection** : Check URLs manually by navigating to common SCM paths.
    * http://target.com/.git/
    * http://target.com/.svn/

* **Automated Tools** : Refer to the page related to the specific technology.

Once a potential SCM folder is identified, check the HTTP response codes and contents. You might need to bypass `.htaccess` or Reverse Proxy rules.

The NGINX rule below returns a `403 (Forbidden)` response instead of `404 (Not Found)` when hitting the `/.git` endpoint.

```ps1
location /.git {
  deny all;
}
```

For example in Git, the exploitation technique doesn't require to list the content of the `.git` folder (http://target.com/.git/), the data extraction can still be conducted when files can be read.


## Labs

* [Root Me - Insecure Code Management](https://www.root-me.org/fr/Challenges/Web-Serveur/Insecure-Code-Management)


## References

- [Hidden directories and files as a source of sensitive information about web application - Apr 30, 2017](https://github.com/bl4de/research/tree/master/hidden_directories_leaks)