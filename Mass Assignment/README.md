# Mass Assignment

> A mass assignment attack is a security vulnerability that occurs when a web application automatically assigns user-supplied input values to properties or variables of a program object. This can become an issue if a user is able to modify attributes they should not have access to, like a user's permissions or an admin flag.

## Summary

* [Methodology](#methodology)
* [Labs](#labs)
* [References](#references)


## Methodology

Mass assignment vulnerabilities are most common in web applications that use Object-Relational Mapping (ORM) techniques or functions to map user input to object properties, where properties can be updated all at once instead of individually. Many popular web development frameworks such as Ruby on Rails, Django, and Laravel (PHP) offer this functionality.

For instance, consider a web application that uses an ORM and has a user object with the attributes `username`, `email`, `password`, and `isAdmin`. In a normal scenario, a user might be able to update their own username, email, and password through a form, which the server then assigns to the user object.

However, an attacker may attempt to add an `isAdmin` parameter to the incoming data like so:

```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true
}
```

If the web application is not checking which parameters are allowed to be updated in this way, it might set the `isAdmin` attribute based on the user-supplied input, giving the attacker admin privileges


## Labs

* [PentesterAcademy - Mass Assignment I](https://attackdefense.pentesteracademy.com/challengedetailsnoauth?cid=1964)
* [PentesterAcademy - Mass Assignment II](https://attackdefense.pentesteracademy.com/challengedetailsnoauth?cid=1922)
* [Root Me - API - Mass Assignment](https://www.root-me.org/en/Challenges/Web-Server/API-Mass-Assignment)


## References

- [Hunting for Mass Assignment - Shivam Bathla - August 12, 2021](https://blog.pentesteracademy.com/hunting-for-mass-assignment-56ed73095eda)
- [Mass Assignment Cheat Sheet - OWASP - March 15, 2021](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [What is Mass Assignment? Attacks and Security Tips - Yoan MONTOYA - June 15, 2023](https://www.vaadata.com/blog/what-is-mass-assignment-attacks-and-security-tips/)