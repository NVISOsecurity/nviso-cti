## NVISO CSIRT ADVISORY
**Update #2 2021-07-21**
* This advisory has been updated to clarify the way this vulnerbility works. Also the workaround was techinically incorrect. Please see that section for the update. 
* Microsoft has released guidance on the mitgation of this vulnerability here: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
* CVE-2021-36934 has been assigned.

**Update #1 2021-07-20**
* SANS has published a diary entry about this issue here: https://isc.sans.edu/diary/27652  <-- Great writeup on how all this works!
* PoC Code has been published: https://github.com/GossiTheDog/HiveNightmare
* Other files also have incorrect ACLs such as %SystemRoot%/system32/config/SECURITY and %SystemRoot%/system32/config/SYSTEM

**2021-07-20**
## SUMMARY
Recently researchers have discovered that the Windows SAM database, storage of local passwords and users, is accessible by non-admin users. This vulnerability, which has not been acknowledged by Microsoft as of the time of this writing, is being dubbed &#35;hivepermission. This advisory will be updated on our Github page as more information becomes available. 

## WHY THIS MATTERS
The issue is that the ACL is incorrectly applied to key system files for normal users. These include %SystemRoot%/system32/config/SAM, %SystemRoot%/system32/config/SECURITY and %SystemRoot%/system32/config/SYSTEM. The files are not accessible under normal circumstances since they are in use when the system is booted up. Since the ACL is set to allow unprivileged read and execute access to these files, you can just grab them from VSS copies. VSS is enabled by default in most situations, so these copies should be available. 

## AFFECTED PRODUCTS
* Win10 1809 and above are vulnerable.
* Win10 1803 and below are not vulnerable. 

## AVAILABLE WORKAROUNDS
**Restrict access to the contents of %windir%\system32\config**

* Open Command Prompt or Windows PowerShell as an administrator.
* Run this command: icacls %windir%\system32\config\*.* /inheritance:e

**Delete Volume Shadow Copy Service (VSS) shadow copies**

* Delete any System Restore points and Shadow volumes that existed prior to restricting access to %windir%\system32\config.
* Create a new System Restore point (if desired).

**Impact of workaround**

Deleting shadow copies could impact restore operations, including the ability to restore data with third-party backup applications.
Note: You must restrict access and delete shadow copies to prevent exploitation of this vulnerability.

## AVAILABLE PATCHES
No patches available at this time. 

## RECOMMENDED ACTIONS
* Monitor for any access to this file path: %SystemRoot%/system32/config/SAM or %SystemRoot%/system32/config/SECURITY or %SystemRoot%/system32/config/SYSTEM.
* Monitor for any access to Volume Shadow Copies, for example: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<#>
* Some EDR tools should pick up on any SAM database dumping activity. 
* Monitoring of LOLBINS is key to this and is good practice to do regardless. The reason to monitor of “living of the land binaries” is because no special tools are needed to exploit this vulnerability.
* Also see the Detection section of the MITRE ATT&CK page for T1003: OS Credential Dumping, Technique T1003 - Enterprise | MITRE ATT&CK® (https://attack.mitre.org/techniques/T1003/).

## CONTACT AND FEEDBACK
Our goal is to provide a fast, brief, and actionable advisory on critical cyber security incidents.
Was this advisory of value to your organization? Was the content clear and concise? Your comments and feedback are very important to us. 
Please do not hesitate to reach out to csirt@nviso.eu   
