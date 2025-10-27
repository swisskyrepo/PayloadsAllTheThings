# DELETE HTTP request

Using http client you can try to delete unprotected web content from database using DELETE http request which tells the underlying web app to execute SQL command like `DELETE FROM users WHERE id = 123;``

## Execution

Assuming the servers for each framework are running on their default ports
and you want to delete the resource with an ID of 123:

### Express.js (Node.js)

```sh
curl -X DELETE http://localhost:3000/users/123
```

### Django (Python)

```sh
curl -X DELETE http://localhost:8000/users/123/
```

### Ruby on Rails (Ruby)

```sh
curl -X DELETE http://localhost:3000/users/123
```

### Spring Boot (Java)

```sh
curl -X DELETE http://localhost:8080/users/123
```

### ASP.NET Core (C#)

```sh
curl -X DELETE http://localhost:5000/Users/123
````

### Laravel (PHP)

```sh
curl -X DELETE http://localhost:8000/api/users/123
```

The server has to implement `DELETE` route handler, in terms of `CRUD` it's the last, delete part.

## Proof of concept

1. Run `masscan` over the whole internet looking for web servers
2. Build a wordlist of _delete api routes_
3. Using web scanner like `dirbuster`, `gobuster` or fuzzer like `ffuf` feed it with `DELETE` http request and wordlist

* This is just an example of APT behaviour
