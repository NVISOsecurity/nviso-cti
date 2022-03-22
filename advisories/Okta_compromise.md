## NVISO CSIRT ADVISORY
**Last update: 2022-03-22**

## SUMMARY
On 22nd of March 2022, the threat actor group Lapsus$ claimed to have had access to Okta’s services for a period of at least two months. The screenshots showed that the “superuser” account also used other apps, including those from Amazon AWS, Zoom, Gmail, Crayon, Splunk, and Atlassian (Jira and Confluence).
LAPSUS$ is the same threat actor group that hit Samsung and NVIDA which could add credence to them having the level of access. The same group also claimed to have access to Microsoft’s Azure DevOps portal and source code repos. 

Since this breach looks to affect the Okta side of the authentication portals, any organization using Okta should assume the access path was compromised. 

![Alt text](/advisories/images/okta_screenshot_032022.jpg?raw=true "Screenshot from LAPSUS$ Telegram channel")

The screenshots showed a timestamp of 2022-02-21 which would match the claim of access for two months but that cannot be confirmed. 
Okta has since released a statement via Reuters, indicating that the company was investigating and would provide updates as information becomes available – it is potentially related to an earlier incident in January: https://www.reuters.com/technology/authentication-services-firm-okta-says-it-is-investigating-report-breach-2022-03-22/ 


## WHY THIS MATTERS

Okta is a major Single Sign-On (SSO) provider, meaning one account can be used to log on to multiple online services or solutions. It sits on the identity layer and as such is a crucial component in modern digital environments – in theory, an attacker that has compromised Okta can also potentially compromise client environments or log in via one service to access another and “hop” over from there. 


## RECOMMENDED ACTIONS

It is advised that all organizations using Okta start an audit of the Okta logs immediately. Look for any abnormal access that differs from a known baseline.
Okta has the capability of showing geolocation and historical login data for users. Examples are abnormal or unexpected logins from IPs or geolocations not in line with typical business-as-usual activities. Gathering and analyzing logs is explained as per the following Okta knowledge base article: https://help.okta.com/en/prod/Content/Topics/Reports/Reports_SysLog.htm   

There are further claims LAPSUS$ actively recruits insiders at Fortune500 and other large organizations. While this statement cannot be verified or confirmed at this point, it is a known fact that a malicious insider can pose a huge risk.  

Insider threats are not a new phenomenon: every organization has likely dealt with or suffered from an insider threat at one point or another, whether it be a risk that was looming such as a disgruntled employee with broad access rights, accidental spillage online (e.g. API key leaks) or as part of an attack campaign initiated by a cybercriminal gang such as LAPSUS$. 

NVISO suggests building out a plan that goes from policy to culture to technology and extends well beyond.  
