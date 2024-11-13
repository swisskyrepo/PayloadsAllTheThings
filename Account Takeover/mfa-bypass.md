# MFA Bypasses

> Multi-Factor Authentication (MFA) is a security measure that requires users to provide two or more verification factors to gain access to a system, application, or network. It combines something the user knows (like a password), something they have (like a phone or security token), and/or something they are (biometric verification). This layered approach enhances security by making unauthorized access more difficult, even if a password is compromised.
> MFA Bypasses are techniques attackers use to circumvent MFA protections. These methods can include exploiting weaknesses in MFA implementations, intercepting authentication tokens, leveraging social engineering to manipulate users or support staff, or exploiting session-based vulnerabilities.

## Summary

* [Response Manipulation](#response-manipulation)
* [Status Code Manipulation](#status-code-manipulation)
* [2FA Code Leakage in Response](#2fa-code-leakage-in-response)
* [JS File Analysis](#js-file-analysis)
* [2FA Code Reusability](#2fa-code-reusability)
* [Lack of Brute-Force Protection](#lack-of-brute-force-protection)
* [Missing 2FA Code Integrity Validation](#missing-2fa-code-integrity-validation)
* [CSRF on 2FA Disabling](#csrf-on-2fa-disabling)
* [Password Reset Disable 2FA](#password-reset-disable-2fa)
* [Backup Code Abuse](#backup-code-abuse)
* [Clickjacking on 2FA Disabling Page](#clickjacking-on-2fa-disabling-page)
* [Enabling 2FA doesn't expire Previously active Sessions](#enabling-2fa-doesnt-expire-previously-active-sessions)
* [Bypass 2FA by Force Browsing](#bypass-2fa-by-force-browsing)
* [Bypass 2FA with null or 000000](#bypass-2fa-with-null-or-000000)
* [Bypass 2FA with array](#bypass-2fa-with-array)

## 2FA Bypasses

### Response Manipulation

In response if `"success":false`
Change it to `"success":true`

### Status Code Manipulation

If Status Code is **4xx**
Try to change it to **200 OK** and see if it bypass restrictions

### 2FA Code Leakage in Response

Check the response of the 2FA Code Triggering Request to see if the code is leaked.

### JS File Analysis

Rare but some JS Files may contain info about the 2FA Code, worth giving a shot

### 2FA Code Reusability

Same code can be reused

### Lack of Brute-Force Protection

Possible to brute-force any length 2FA Code

### Missing 2FA Code Integrity Validation

Code for any user acc can be used to bypass the 2FA

### CSRF on 2FA Disabling

No CSRF Protection on disabling 2FA, also there is no auth confirmation

### Password Reset Disable 2FA

2FA gets disabled on password change/email change

### Backup Code Abuse

Bypassing 2FA by abusing the Backup code feature
Use the above mentioned techniques to bypass Backup Code to remove/reset 2FA restrictions

### Clickjacking on 2FA Disabling Page

Iframing the 2FA Disabling page and social engineering victim to disable the 2FA

### Enabling 2FA doesn't expire Previously active Sessions

If the session is already hijacked and there is a session timeout vuln

### Bypass 2FA by Force Browsing

If the application redirects to `/my-account` url upon login while 2Fa is disabled, try replacing `/2fa/verify` with `/my-account` while 2FA is enabled to bypass verification.

### Bypass 2FA with null or 000000

Enter the code **000000** or **null** to bypass 2FA protection.

### Bypass 2FA with array

```json
{
    "otp":[
        "1234",
        "1111",
        "1337", // GOOD OTP
        "2222",
        "3333",
        "4444",
        "5555"
    ]
}
```
