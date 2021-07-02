# Indicators and detection ruling for June

## Content

| Name | Type | Source |
|------|----------|----------|
| SkinnyBoy.yar | Yara rule | Sector25|
| june_iocs.csv | IOC list in CSV format | MISP|

## Additional ruling

Sigma rules for the PrintNightmare vulnerability can be found as follows:
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/sysmon_cve_2021_1675_print_nightmare.yml
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/malware/av_printernightmare_cve_2021_1675.yml
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_susp_failed_guest_logon.yml
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file_event/win_cve_2021_1675_printspooler.yml
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_exploit_cve_2021_1675_printspooler.yml
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file_delete/win_cve_2021_1675_printspooler_del.yml
