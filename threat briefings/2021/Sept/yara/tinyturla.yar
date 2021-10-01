import "pe"
rule TinyTurla {
meta:
author = "Cisco Talos"
description = "Detects Tiny Turla backdoor DLL"
strings:
$a = "Title:"
$b = "Hosts" fullword wide
$c = "Security" fullword wide
$d = "TimeLong" fullword wide
$e = "TimeShort" fullword wide
$f = "MachineGuid" fullword wide
$g = "POST" fullword wide
$h = "WinHttpSetOption" fullword ascii
$i = "WinHttpQueryDataAvailable" fullword ascii

condition:
pe.is_pe and
pe.characteristics & pe.DLL and
pe.exports("ServiceMain") and
all of them
}
