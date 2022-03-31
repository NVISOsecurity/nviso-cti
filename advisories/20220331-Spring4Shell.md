# NVISO CSIRT ADVISORY
__DATE (2022-03-31)__

## SUMMARY
Between March 28th and March 29th two vulnerabilities and one misconfiguration affecting the popular Java-based Spring projects were disclosed. The impact, depending on the weakness, can range from a Denial of Service (DoS) up to Remote Code Execution (RCE).

The Spring projects (Spring Framework and Spring Cloud Functions) are commonly used in the Java ecosystem and often deployed on Java-based servers such as Apache Tomcat. Java-based servers/applications are used across a wide variety of the industry as was observed late 2021 with the Log4Shell vulnerability (CVE-2021-44228).

While the vulnerabilities have available patches, the misconfiguration item is recorded in the Spring documentation and requires Spring-based code-bases to implement safeguards against potential abuses. __Successful abuse may lead to RCE (Remote Code Execution)__.

### Spring Framework
The Spring Framework is a popular application framework for the Java language providing developers with generic modules easing application development (authentication, authorization, data access, MVC, ...). The wide variety of modules has resulted in the Spring Framework being one of the most widely-used frameworks within the Java application ecosystem.

A common weak configuration in Spring Framework’s DataBinder usage was discovered which, when abused, can lead to __remote code execution__ in your Spring Core applications.

Furthermore, as reported by [this VMWare advisory](https://tanzu.vmware.com/security/cve-2022-22950), Spring Framework versions 5.3.0 - 5.3.16 and older unsupported versions are vulnerable to a __denial of service attack__ (CVE-2022-22950). It is possible for a user to provide a specially crafted SpEL ([Spring Expression Language](https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/expressions.html)) expression that may cause a denial of service. 

### Spring Cloud Functions
Spring Cloud is a Spring project aimed at easing Spring application deployment within cloud environments by providing concepts such as distributed configuration, distributed messaging, service discovery and more. Spring Cloud’s Functions module abstracts away all of the transport details within the Cloud environment and infrastructure to allow the developer focus firmly on business logic.

As reported by [the advisory](https://tanzu.vmware.com/security/cve-2022-22963), Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions are vulnerable to a __local resource inclusion__ (CVE-2022-22963). When using the optional routing functionality, it is possible for a user to provide a specially crafted SpEL ([Spring Expression Language](https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/expressions.html)) as a routing-expression that may result in access to local resources.

## WHY THIS MATTERS
__While both vulnerabilities have patches available, the common weak configuration leading to a remote code execution is likely to affect many projects leveraging Spring Framework’s DataBinder. DataBinder would require additional configuration to be secured while it properly operates as a data binder without (also referred to as insecure defaults). Furthermore, sample projects and code snippets provided by the Spring guides do not configure the restrictions required to prevent successful exploitation (e.g.: the “[Handling Form Submission](https://spring.io/guides/gs/handling-form-submission/)” guide [as of 2022-03-31](https://github.com/spring-guides/gs-handling-form-submission/tree/066ce64bf0933f0f8b1aa939e40b05985dec4c8d)), resulting in developers commonly adopting similar bad practices.__

__Multiple exploits are publicly available resulting in remote code execution within Spring Core applications. Certain exploits have been confirmed to achieve RCE.__

## AFFECTED PRODUCTS
-	Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions for the patchable CVE-2022-22963.
-	Spring Framework versions 5.3.0 - 5.3.16 and older unsupported versions for the patchable  CVE-2022-22950.
-	Spring Framework-based projects leveraging the DataBinder and running on Java 9 or newer for the common weak configuration.

## AVAILABLE WORKAROUNDS
While both vulnerabilities have available patches, fixing the weak configuration requires implementing additional code as outlined in the [Spring Framework’s DataBinder documentation](https://docs.spring.io/spring-framework/docs/2.0.x/javadoc-api/org/springframework/validation/DataBinder.html).

### Spring Framework

To prevent the abuse of the DataBinder, it is possible to restrict the fields that should be allowed for binding through [`DataBinder#setAllowedFields`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/validation/DataBinder.html#setAllowedFields-java.lang.String...-). In situations where the set of fields is unknown, it is possible to prohibit the binding of currently abused fields through [`DataBinder#setDisallowedFields`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/validation/DataBinder.html#setDisallowedFields-java.lang.String...-). *Praetorian* released an application-wide mitigation based on the deny-list approach at “[Spring Core on JDK9+ is vulnerable to remote code execution](https://www.praetorian.com/blog/spring-core-jdk9-rce/)”. The following code enforces an application-wide deny-list on all controllers by calling their respective DataBinder’s `setDisallowedFields` method:

```java
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.InitBinder;

@ControllerAdvice
@Order(10000)
public class BinderControllerAdvice {
    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder) {
         String[] denylist = new String[]{"class.*", "Class.*", "*.class.*", "*.Class.*"};
         dataBinder.setDisallowedFields(denylist);
    }
}
```

## AVAILABLE PATCHES
-	Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions have CVE-2022-22963 fixed in versions 3.1.7 and 3.2.3.
-	Spring Framework versions 5.3.0 - 5.3.16 and older unsupported versions have CVE-2022-22950 fixed in versions 5.3.17 and 5.2.20 (back-ported).
-	No patches are available for the common weak configuration. NVISO assesses there is a low probability that the Spring Framework will release a patch to move to a “secure-by-default” DataBinder. As such we recommend you refer to the below recommended actions.

## CVSS SCORE AND CVE ID
| CVE ID | Severity | CVSSv3 Score |
|--------|----------|--------------|
| [CVE-2022-22950](https://tanzu.vmware.com/security/cve-2022-22950) | Medium | 5.4 |
| [CVE-2022-22963](https://tanzu.vmware.com/security/cve-2022-22963) | Medium | 5.4 |

NIST: http://nvd.nist.gov/vuln/detail/CVE-2020-22950

NIST: http://nvd.nist.gov/vuln/detail/CVE-2020-22963

MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-22950

MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-22963

## RECOMMENDED ACTIONS
We recommend to review Java-based projects within your environment to identify and update any vulnerable Spring Cloud Functions and Spring Core libraries to patched versions as mentioned above.

We also encourage organizations to review Java-based projects leveraging the Spring Framework’s DataBinder to ensure the Binders’ `AllowedFields` properties are configured as mentioned in the above workarounds.

NVISO has observed that the currently available proof-of-concepts (PoC) altering the logging configuration will not log exploitation in case of success. While these successful exploits will also terminate logging into the access logs, attackers have the capability to revert these changes later-on. Failed exploits tend to pollute or break the logs. As such, identifying anomalies in the access logs (broken format, outdated entries, ...) may indicate attempts of exploitation. Future adaptations of the PoC may not rely on logging alterations and may hence obtain RCE (remote code execution) through other means.

Finally, it is recommended to protect Java-based servers with:
-	A WAF (web-application firewall) to block some of the currently known exploits abusing the weaknesses.
-	An AV (antivirus) and/or EDR (endpoint-detection and response) solution to block parts of the currently known exploits or dropped post-exploitation toolkits (e.g. web-shells).

## CONTACT AND FEEDBACK
Our goal is to provide a fast, brief, and actionable advisory on critical cyber security incidents.

Was this advisory of value to your organization? Was the content clear and concise? Your comments and feedback are very important to us. 

Please do not hesitate to reach out to threatintel@nviso.eu
