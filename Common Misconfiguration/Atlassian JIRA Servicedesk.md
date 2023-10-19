### Misconfigured Atlassian ServiceDesks ThatAllows Public Sign Ups

This vulnerability allows attackers to access internal service desks that have been improperly exposed to the public internet. The steps to exploit it are:

    1. Identify the Atlassian service desk URL of the target organization, usually in the format https://companyname.atlassian.net
    2. Navigate to the service desk customer login page URL: https://companyname.atlassian.net/servicedesk/customer/user/login
    3. If the service desk allows public registration, there will be an option to sign up for an account
    4. Sign up for an account using any email address
    5. You will now have access to the organization's internal service desk portals.

This vulnerability can impact service desks used for IT, HR, Facilities, Finance, Legal, etc. The default settings allow public sign-ups without any authentication. By following these simple steps, attackers can gain unauthorized access to sensitive internal information.

Refer: https://medium.com/@intideceukelaire/hundreds-of-internal-servicedesks-exposed-due-to-covid-19-ecd0baec87bd
