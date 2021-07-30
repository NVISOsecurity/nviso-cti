rule Sodinokibi_032021 {
meta:
description = "files - file DomainName.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-03-21"
hash1 = "2896b38ec3f5f196a9d127dbda3f44c7c29c844f53ae5f209229d56fd6f2a59c"
strings:
$s1 = "vmcompute.exe" fullword wide
$s2 = "vmwp.exe" fullword wide
$s3 = "bootcfg /raw /a /safeboot:network /id 1" fullword ascii
$s4 = "bcdedit /set {current} safeboot network" fullword ascii
$s5 = "7+a@P>:N:0!F$%I-6MBEFb M" fullword ascii
$s6 = "jg:\"\\0=Z" fullword ascii
$s7 = "ERR0R D0UBLE RUN!" fullword wide
$s8 = "VVVVVPQ" fullword ascii
$s9 = "VVVVVWQ" fullword ascii
$s10 = "Running" fullword wide /* Goodware String - occured 159 times */
$s11 = "expand 32-byte kexpand 16-byte k" fullword ascii
$s12 = "9RFIT\"&" fullword ascii
$s13 = "jZXVf9F" fullword ascii
$s14 = "tCWWWhS=@" fullword ascii
$s15 = "vmms.exe" fullword wide /* Goodware String - occured 1 times */
$s16 = "JJwK9Zl" fullword ascii
$s17 = "KkT37uf4nNh2PqUDwZqxcHUMVV3yBwSHO#K" fullword ascii
$s18 = "0*090}0" fullword ascii /* Goodware String - occured 1 times */
$s19 = "5)5I5a5" fullword ascii /* Goodware String - occured 1 times */
$s20 = "7-7H7c7" fullword ascii /* Goodware String - occured 1 times */
condition:
uint16(0) == 0x5a4d and filesize < 400KB and
( pe.imphash() == "031931d2f2d921a9d906454d42f21be0" or 8 of them )
}
