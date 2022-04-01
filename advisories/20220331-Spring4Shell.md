# NVISO CSIRT ADVISORY
__DATE (2022-03-31), [UPDATED](https://github.com/NVISOsecurity/nviso-cti/commits/master/advisories/20220331-Spring4Shell.md) (2022-04-01)__

## SUMMARY
Between March 28th and March 29th three vulnerabilities (one highlighting a common weak configuration) affecting the popular Java-based Spring projects were disclosed. The impact, depending on the weakness, can range from a Denial of Service (DoS) up to Remote Code Execution (RCE).

The Spring projects (Spring Framework, Spring Boot and Spring Cloud Functions) are commonly used in the Java ecosystem and often deployed on Java-based servers such as Apache Tomcat. Java-based servers/applications are used across a wide variety of the industry as was observed late 2021 with the Log4Shell vulnerability (CVE-2021-44228).

While all vulnerabilities have available patches, the insecure data-binding is recorded in the Spring documentation and requires Spring-based code-bases to implement safeguards against potential further abuses. __Successful abuse may lead to RCE (Remote Code Execution)__.

### Spring Framework (incl. dependent Spring Boot)
The Spring Framework is a popular application framework for the Java language providing developers with generic modules easing application development (authentication, authorization, data access, MVC, ...). The wide variety of modules has resulted in the Spring Framework being one of the most widely-used frameworks within the Java application ecosystem.

An insecure data-binding in the Spring Framework’s DataBinder usage was discovered (see [VMWare advisory](https://tanzu.vmware.com/security/cve-2022-22965)) which, when abused, can lead to __remote code execution__ (CVE-2022-22965) in your Spring Core applications. A typical abuse of this vulnerability can consist of intruders deploying a reverse shell on your infrastructure. While patches prevent the currently known abuses, [Spring's early RCE announcement](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement) correctly highlights that there may be further ways to abuse the data-binding feature unless developers implement additional safeguards.

Furthermore, as reported by [this VMWare advisory](https://tanzu.vmware.com/security/cve-2022-22950), Spring Framework versions 5.3.0 - 5.3.16 and older unsupported versions are vulnerable to a __denial of service attack__ (CVE-2022-22950). It is possible for a user to provide a specially crafted SpEL ([Spring Expression Language](https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/expressions.html)) expression that may cause a denial of service. 

### Spring Cloud Functions
Spring Cloud is a Spring project aimed at easing Spring application deployment within cloud environments by providing concepts such as distributed configuration, distributed messaging, service discovery and more. Spring Cloud’s Functions module abstracts away all of the transport details within the Cloud environment and infrastructure to allow the developer focus firmly on business logic.

As reported by [the advisory](https://tanzu.vmware.com/security/cve-2022-22963), Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions are vulnerable to a __local resource inclusion__ (CVE-2022-22963). When using the optional routing functionality, it is possible for a user to provide a specially crafted SpEL ([Spring Expression Language](https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/expressions.html)) as a routing-expression that may result in access to local resources.

## WHY THIS MATTERS
__While all vulnerabilities have patches available, the insecure data-binding leading to a remote code execution is likely to affect many projects leveraging Spring Framework’s DataBinder. DataBinder would require additional configuration to be secured while it properly operates as a data binder without (also referred to as insecure defaults). Furthermore, sample projects and code snippets provided by the Spring guides do not configure the restrictions required to prevent successful exploitation (e.g.: the “[Handling Form Submission](https://spring.io/guides/gs/handling-form-submission/)” guide [as of 2022-03-31](https://github.com/spring-guides/gs-handling-form-submission/tree/066ce64bf0933f0f8b1aa939e40b05985dec4c8d)), resulting in developers commonly adopting similar bad practices.__

__Multiple exploits are publicly available resulting in remote code execution within Spring Core applications. Certain exploits have been confirmed to achieve RCE.__

## AFFECTED PRODUCTS
-	Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions for the patchable CVE-2022-22963.
-	Spring Framework versions 5.3.0 - 5.3.16 and older unsupported versions for the patchable  CVE-2022-22950.
-	Spring Framework versions 5.3.0 - 5.3.17, 5.2.0 - 5.2.19 and older unsupported versions for the patchable CVE-2022-22965.
-	Spring Boot versions 2.6.5, 2.5.11 and older unsupported versions are dependent on vulnerable Spring Framework versions.
-	Spring Framework-based projects leveraging the DataBinder and running on Java Development Kit (JDK) 9 or newer, packaged as a WAR archive, for the common weak configuration.

## AVAILABLE WORKAROUNDS
While all vulnerabilities have available patches, fixing the weak configuration requires implementing additional code as outlined in the [Spring Framework’s DataBinder documentation](https://docs.spring.io/spring-framework/docs/2.0.x/javadoc-api/org/springframework/validation/DataBinder.html).

### Spring Framework

#### All Versions (incl. Patched, Preferred)
To prevent the abuse of the DataBinder, developers should restrict the fields allowed for binding through [`DataBinder#setAllowedFields`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/validation/DataBinder.html#setAllowedFields-java.lang.String...-). 

#### Unpatched Versions (Fallback)
In situations where the set of fields is unknown (rendering the above mitigation impossible), it is possible to prohibit the binding of currently abused fields through [`DataBinder#setDisallowedFields`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/validation/DataBinder.html#setDisallowedFields-java.lang.String...-). This deny-list approach does however only protect against currently known abuses as opposed to the above allow-list approach. *Spring* released multiple suggested work-arounds as application-wide mitigations based on this deny-list approach at “[Spring Framework RCE, Early Announcement](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)”.

## AVAILABLE PATCHES
-	Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions have CVE-2022-22963 fixed in versions 3.1.7 and 3.2.3.
-	Spring Framework versions 5.3.x should upgrade to 5.3.18+ to fix CVE-2022-22950 and CVE-2022-22965. 
-	Spring Framework versions 5.2.x should upgrade to 5.2.20+ to fix CVE-2022-22950 and CVE-2022-22965.
-	Spring Boot (dependent on Spring Framework) versions 2.6.x should upgrade to 2.6.6+ in order to include the updated Spring Framework (5.3.18) dependency for CVE-2022-22965.
-	Spring Boot (dependent on Spring Framework) versions 2.5.x should upgrade to 2.5.12+ in order to include the updated Spring Framework (5.3.18) dependency for CVE-2022-22965. 

While a partial patch is available for the insecure data-binding. NVISO assesses there is a low probability that the Spring Framework will release a patch to move to a “secure-by-default” DataBinder. As such we recommend you refer to the below recommended actions.

## CVSS SCORE AND CVE ID
| CVE ID | Severity | CVSSv3 Score |
|--------|----------|--------------|
| [CVE-2022-22950](https://tanzu.vmware.com/security/cve-2022-22950) | Medium | 5.4 |
| [CVE-2022-22963](https://tanzu.vmware.com/security/cve-2022-22963) | Critical | 9.8 |
| [CVE-2022-22965](https://tanzu.vmware.com/security/cve-2022-22965) | Critical | 9.8 |

NIST: http://nvd.nist.gov/vuln/detail/CVE-2020-22950

NIST: http://nvd.nist.gov/vuln/detail/CVE-2020-22963

NIST: http://nvd.nist.gov/vuln/detail/CVE-2020-22965

MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-22950

MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-22963

MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-22965

## RECOMMENDED ACTIONS
We recommend to review Java-based projects within your environment to identify and update any vulnerable Spring Cloud Functions, Spring Core and Spring Boot libraries (Spring Framework) to patched versions as mentioned above. Considering exploit code is available it is recommended to prioritize the deployment of upgrading to 5.2.20+ or 5.3.18+.

We also encourage organizations to review Java-based projects leveraging the Spring Framework’s DataBinder to ensure the Binders’ `AllowedFields` properties are configured as mentioned in the above workarounds.

NVISO has observed that the currently available proof-of-concepts (PoC) altering the logging configuration will not log exploitation in case of success. While these successful exploits will also terminate logging into the access logs, attackers have the capability to revert these changes later-on. Failed exploits tend to pollute or break the logs. As such, identifying anomalies in the access logs (broken format, outdated entries, ...) may indicate attempts of exploitation. Future adaptations of the PoC may not rely on logging alterations and may hence obtain RCE (remote code execution) through other means.

Finally, it is recommended to protect Java-based servers with:
-	A WAF (web-application firewall) to block some of the currently known exploits abusing the weaknesses.
-	An AV (antivirus) and/or EDR (endpoint-detection and response) solution to block parts of the currently known exploits or dropped post-exploitation toolkits (e.g. web-shells).

## CONTACT AND FEEDBACK
Our goal is to provide a fast, brief, and actionable advisory on critical cyber security incidents.

Was this advisory of value to your organization? Was the content clear and concise? Your comments and feedback are very important to us. 

Please do not hesitate to reach out to threatintel@nviso.eu

## MORE INFORMATION
More information can be found on the links below.

- Security Analysis of the latest Java RCE '0-day' vulnerabilities in Spring: [https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/](https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/)
- CVE-2022-22965: Spring Core Remote Code Execution Vulnerability Exploited In the Wild (SpringShell) [https://unit42.paloaltonetworks.com/cve-2022-22965-springshell/](https://unit42.paloaltonetworks.com/cve-2022-22965-springshell/)
