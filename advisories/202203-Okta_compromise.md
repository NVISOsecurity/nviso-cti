## NVISO CSIRT ADVISORY
**Last update: 2022-03-23**

## SUMMARY

On 22nd of March 2022, the threat actor group Lapsus$ claimed to have had access to Okta’s services for a period of at least two months. The screenshots showed that the “superuser” account also used other apps, including those from Amazon AWS, Zoom, Gmail, Crayon, Splunk, and Atlassian (Jira and Confluence).
LAPSUS$ is the same threat actor group that hit Samsung and NVIDIA which could add credence to them having the level of access. The same group also claimed to have access to Microsoft’s Azure DevOps portal and source code repos. 

Since this breach seems to affect the Okta side of the authentication portals, any organization using Okta should assume the access path was compromised. 

![Alt text](/advisories/images/okta_screenshot_032022.jpg?raw=true "Screenshot from LAPSUS$ Telegram channel")

The screenshots showed a timestamp of 2022-02-21 which would match the claim of access for two months but that cannot be confirmed. 
Okta has since released a statement, indicating that in January 2022, they detected an attempt to compromise the account of a third-party customer support engineer at one of their sub-processors, and believe the screenshots LAPSUS$ shared are connected to this January event:
https://sec.okta.com/articles/2022/03/official-okta-statement-lapsus-claims  

## UPDATE 2022-03-23

Okta released two additional statements that they "detected an attempt to compromise the account of a third-party customer support engineer working for one of our subprocessors," but that "the matter was investigated and contained by the subprocessor." The expanded statement included the assessment that "a five-day window of time between January 16-21, 2022, where an attacker had access to a support engineer’s laptop." Okta went on to say that the access they had would not include the ability to create or delete users or access user's existing passwords but that it would have included access to the ticketing system, list of users, and the ability to reset MFA tokens and passwords. We expect more clarity around Okta's statements as it is seems they are more in a "reactive mode". Okta's updated statement can be found here:
https://www.okta.com/blog/2022/03/updated-okta-statement-on-lapsus/

- Lapsus$ responded to Okta's denial of a full breach with a list of comments on their Telegram channel pointing to weaknesses at Okta. Lapsus$ claims to have been able to access 95% of Okta's client base while Okta limits the access to only 2.5%. See screenshot below.

- Lapsus$ also claimed to have breached Microsoft as well as many other companies and has leaked the "source code" of Bing and Bing Maps and Cortana to prove their Microsoft compromise. Security researchers are pouring over the data currently and it appears to be legitimate code from official Microsoft repositories. Lapsus$ also claims to have breached LGE again. They have not released the full extent of the data they captured at this time but did provide hashes of that data.

- Lapsus$ seems to enjoy the furore that they stir up during these posts and sometimes ruin their foothold in a breached company by announcing the access to the world. They state that they do not care about this access being removed which points their motivation being that of cyber-anarchy.

### Telegram screenshot

![Alt text](/advisories/images/lapsus%24_telegram_screenshot.png?raw=true "Telegram screenshot")


## WHY THIS MATTERS

Okta is a major Single Sign-On (SSO) provider, meaning one account can be used to log on to multiple online services or solutions. It sits on the identity layer and as such is a crucial component in modern digital environments – in theory, an attacker that has compromised Okta can also potentially compromise client environments or log in via one service to access another and “hop” over from there. 


## RECOMMENDED ACTIONS

It is advised that all organizations using Okta start an audit of the Okta logs immediately. Look for any abnormal access that differs from a known baseline.

Okta has the capability of showing geolocation and historical login data for users. Examples are abnormal or unexpected logins from IPs or geolocations not in line with typical business-as-usual activities. 

Gathering and analyzing logs is explained as per the following Okta knowledge base article: https://help.okta.com/en/prod/Content/Topics/Reports/Reports_SysLog.htm   

Public Sigma rules for Okta log correlation are available here: https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/okta

## MITRE ATT&CK for Lapsus$

|MITRE ATT&CK ID|Technique|Tactic|
|---|---|---|
|T1210|Exploitation of Remote Services|Lateral Movement|
|T1078|Valid Accounts|Initial Access, Defense Evasion, Persistence|
|T1021|Remote Services|Lateral Movement|
