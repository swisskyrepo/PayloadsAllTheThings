# Business Logic Errors

> Business logic errors, also known as business logic flaws, are a type of application vulnerability that stems from the application's business logic, which is the part of the program that deals with real-world business rules and processes. These rules could include things like pricing models, transaction limits, or the sequences of operations that need to be followed in a multi-step process.


## Summary

* [Methodology](#methodology)
    * [Review Feature Testing](#review-feature-testing)
    * [Discount Code Feature Testing](#discount-code-feature-testing)
    * [Delivery Fee Manipulation](#delivery-fee-manipulation)
    * [Currency Arbitrage](#currency-arbitrage)
    * [Premium Feature Exploitation](#premium-feature-exploitation)
    * [Refund Feature Exploitation](#refund-feature-exploitation)
    * [Cart/Wishlist Exploitation](#cartwishlist-exploitation)
    * [Thread Comment Testing](#thread-comment-testing)
* [References](#references)


## Methodology

Unlike other types of security vulnerabilities like SQL injection or cross-site scripting (XSS), business logic errors do not rely on problems in the code itself (like unfiltered user input). Instead, they take advantage of the normal, intended functionality of the application, but use it in ways that the developer did not anticipate and that have undesired consequences.

Common examples of Business Logic Errors.

### Review Feature Testing

* Assess if you can post a product review as a verified reviewer without having purchased the item.
* Attempt to provide a rating outside of the standard scale, for instance, a 0, 6 or negative number in a 1 to 5 scale system.
* Test if the same user can post multiple ratings for a single product. This is useful in detecting potential race conditions.
* Determine if the file upload field permits all extensions; developers often overlook protections on these endpoints.
* Investigate the possibility of posting reviews impersonating other users.
* Attempt Cross-Site Request Forgery (CSRF) on this feature, as it's frequently unprotected by tokens.


### Discount Code Feature Testing

* Try to apply the same discount code multiple times to assess if it's reusable.
* If the discount code is unique, evaluate for race conditions by applying the same code for two accounts simultaneously.
* Test for Mass Assignment or HTTP Parameter Pollution to see if you can apply multiple discount codes when the application is designed to accept only one.
* Test for vulnerabilities from missing input sanitization such as XSS, SQL Injection on this feature.
* Attempt to apply discount codes to non-discounted items by manipulating the server-side request.


### Delivery Fee Manipulation

* Experiment with negative values for delivery charges to see if it reduces the final amount.
* Evaluate if free delivery can be activated by modifying parameters.


### Currency Arbitrage

* Attempt to pay in one currency, for example, USD, and request a refund in another, like EUR. The difference in conversion rates could result in a profit.
    

### Premium Feature Exploitation

* Explore the possibility of accessing premium account-only sections or endpoints without a valid subscription.
* Purchase a premium feature, cancel it, and see if you can still use it after a refund.
* Look for true/false values in requests/responses that validate premium access. Use tools like Burp's Match & Replace to alter these values for unauthorized premium access.
* Review cookies or local storage for variables validating premium access.


### Refund Feature Exploitation

* Purchase a product, ask for a refund, and see if the product remains accessible.
* Look for opportunities for currency arbitrage.
* Submit multiple cancellation requests for a subscription to check the possibility of multiple refunds.


### Cart/Wishlist Exploitation

* Test the system by adding products in negative quantities, along with other products, to balance the total.
* Try to add more of a product than is available.
* Check if a product in your wishlist or cart can be moved to another user's cart or removed from it.


### Thread Comment Testing

* Check if there's a limit to the number of comments on a thread.
* If a user can only comment once, use race conditions to see if multiple comments can be posted.
* If the system allows comments by verified or privileged users, try to mimic these parameters and see if you can comment as well.
* Attempt to post comments impersonating other users.


## References

- [Business Logic Vulnerabilities - PortSwigger - 2024](https://portswigger.net/web-security/logic-flaws)
- [Business Logic Vulnerability - OWASP - 2024](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability)
- [CWE-840: Business Logic Errors - CWE - March 24, 2011](https://cwe.mitre.org/data/definitions/840.html)
- [Examples of Business Logic Vulnerabilities - PortSwigger - 2024](https://portswigger.net/web-security/logic-flaws/examples)