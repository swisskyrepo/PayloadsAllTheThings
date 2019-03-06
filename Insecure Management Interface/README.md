# Insecure management interface

## Springboot-Actuator

Actuator endpoints let you monitor and interact with your application. 
Spring Boot includes a number of built-in endpoints and lets you add your own. 
For example, the health endpoint provides basic application health information. 
Some of them contains sensitive info such as :

- `/trace` (by default the last 100 HTTP requests with headers)
- `/env` (the current environment properties)
- `/heapdump` (builds and returns a heap dump from the JVM used by our application). 

These endpoints are enabled by default in Springboot 1.X. Since Springboot 2.x only `/health` and `/info` are enabled by default.


## References

* [Springboot - Official Documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-endpoints.html)
