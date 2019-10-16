> Kubernetes is an open-source container-orchestration system for automating application deployment, scaling, and management. It was originally designed by Google, and is now maintained by the Cloud Native Computing Foundation.

### API addresses that you should know *(External network visibility)*
---
#### - cAdvisor
```
curl -k https://<IP Address>:4194
```
#### - Insecure API server
```
curl -k https://<IP Address>:8080
```
#### - Secure API Server
```
curl -k https://<IP Address>:(8|6)443/swaggerapi
curl -k https://<IP Address>:(8|6)443/healthz
curl -k https://<IP Address>:(8|6)443/api/v1
```
#### - etcd API
```
curl -k https://<IP address>:2379
curl -k https://<IP address>:2379/version
```
#### - Kubelet API
```
curl -k https://<IP address>:10250
curl -k https://<IP address>:10250/metrics
curl -k https://<IP address>:10250/pods
```
#### - kubelet (Read only)
```
curl -k https://<IP Address>:10255
```
----
### Tools for detecting misconfigurations in Kubernetes:
---

* [kubeaudit](https://github.com/Shopify/kubeaudit). kubeaudit is a command line tool to audit Kubernetes clusters for various different security concerns: run the container as a non-root user, use a read only root filesystem, drop scary capabilities, don't add new ones, don't run privileged, ...
* [kubesec.io](https://kubesec.io/). Security risk analysis for Kubernetes resources.
* [kube-bench](https://github.com/aquasecurity/kube-bench). kube-bench is a Go application that checks whether Kubernetes is deployed securely by running the checks documented in the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/).

* [katacoda](https://katacoda.com/courses/kubernetes). Learn Kubernetes using interactive broser-based scenarios.
