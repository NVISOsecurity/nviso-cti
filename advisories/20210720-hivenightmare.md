## NVISO CSIRT ADVISORY

**2021-07-20**
## SUMMARY
Recently researchers have discovered that the Windows SAM database, storage of local passwords and users, is accessible by non-admin users. This vulnerability, which has not been acknowledged by Microsoft as of the time of this writing, is being dubbed hivenightmare. This advisory will be updated on our Github page as more information becomes available. 
## WHY THIS MATTERS
This vulnerability allows the SAM database to be read by non-admin users. This would allow for trivial local privilege escalation.  

## AFFECTED PRODUCTS
* Win10 1809 and above are vulnerable, whether fresh build or upgrade. 
* Win10 1803 and below are not vulnerable. 

## AVAILABLE WORKAROUNDS
The volume shadow copy service could be disabled but this would also limit the ability to recover lost files, do system restores, etc. This is not recommended. 

## AVAILABLE PATCHES
Microsoft has not commented on this vulnerability as of the time of this writing. 

## RECOMMENDED ACTIONS
* Monitor for any access to this file path: %SystemRoot%/system32/config/SAM. 
* EDR tools should pick up on any SAM database dumping activity. 
* Monitoring of LOLBINS is key to this and is good practice to do regardless. 
* Also see the Detection section of the MITRE ATT&CK page for T1003: OS Credential Dumping, Technique T1003 - Enterprise | MITRE ATT&CK® (https://attack.mitre.org/techniques/T1003/).

## CONTACT AND FEEDBACK
Our goal is to provide a fast, brief, and actionable advisory on critical cyber security incidents.
Was this advisory of value to your organization? Was the content clear and concise? Your comments and feedback are very important to us. 
Please do not hesitate to reach out to csirt@nviso.eu   
