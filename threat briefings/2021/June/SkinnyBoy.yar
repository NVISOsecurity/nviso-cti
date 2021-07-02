rule APT28_SkinnyBoy_Dropper: RUSSIAN THREAT ACTOR {
meta:
author = "Cluster25"
hash1 = "12331809c3e03d84498f428a37a28cf6cbb1dafe98c36463593ad12898c588c9"
strings:
$ = "cmd /c DEL " ascii
//$ = " \"" ascii //NVISO commented
$ = {8a 08 40 84 c9 75 f9}
$ = {0f b7 84 0d fc fe ff ff 66 31 84 0d fc fd ff ff}
condition:
 (uint16(0) == 0x5A4D and all of them)
}

rule APT28_SkinnyBoy_Launcher: RUSSIAN THREAT ACTOR {
meta:
author = "Cluster25"
hash1 ="2a652721243f29e82bdf57b565208c59937bbb6af4ab51e7b6ba7ed270ea6bce"
strings:
$sha = {F4 EB 56 52 AF 4B 48 EE 08 FF 9D 44 89 4B D5 66 24 61 2A 15 1D 58 14 F9 6D 97
13 2C 6D 07 6F 86}
$l1 = "CryptGetHashParam" ascii
$l2 = "CryptCreateHash" ascii
$l3 = "FindNextFile" ascii
$l4 = "PathAddBackslashW" ascii
$l5 = "PathRemoveFileSpecW" ascii
$h1 = {50 6A 00 6A 00 68 0C 80 00 00 FF ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A 00
56 ?? ?? ?? ?? 50 FF ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ??}
$h2 = {8B 01 3B 02 75 10 83 C1 04 83 C2 04 83 EE 04 73 EF}
condition:
uint16(0) == 0x5a4d and filesize < 100KB and ($sha or (all of ($l*) and all of ($h*)))
}

import "pe"
rule APT28_SkinnyBoy_Implanter: RUSSIAN THREAT ACTOR {
meta:
author= "Cluster25"
date= "2021-05-24"
hash= "ae0bc3358fef0ca2a103e694aa556f55a3fed4e98ba57d16f5ae7ad4ad583698"
strings:
$enc_string = {F3 0F 7E 05 ?? ?? ?? ?? 6? [5] 6A ?? 66 [6] 66 [7] F3 0F 7E 05 ?? ?? ?? ?? 8D
85 [4] 6A ?? 50 66 [7] E8}
$heap_ops = {8B [1-5] 03 ?? 5? 5? 6A 08 FF [1-6] FF ?? ?? ?? ?? ?? [0-6] 8B ?? [0-6] 8?}
$xor_cycle = { 8A 8C ?? ?? ?? ?? ?? 30 8C ?? ?? ?? ?? ?? 42 3B D0 72 }
condition:
uint16(0) == 0x5a4d and pe.is_dll() and filesize < 100KB and $xor_cycle and $heap_ops and
$enc_string
}