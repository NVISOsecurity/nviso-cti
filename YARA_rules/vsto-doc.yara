// https://blog.nviso.eu

rule ole_vsto {
	strings:
	    $ole = { D0 CF 11 E0 }
        $assemblylocation = {12 00 00 00 5F 41 73 73 65 6D 62 6C 79 4C 6F 63 61 74 69 6F 6E}
        $assemblyname = {0E 00 00 00 5F 41 73 73 65 6D 62 6C 79 4E 61 6D 65}
        $word =       { 57 00 6F 00 72 00 64 00 44 00 6F 00 63 00 75 00 6D 00 65 00 6E 00 74 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$excel =      { 57 00 6F 00 72 00 6B 00 62 00 6F 00 6F 00 6B 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$powerpoint = { 50 00 6F 00 77 00 65 00 72 00 50 00 6F 00 69 00 6E 00 74 00 20 00 44 00 6F 00 63 00 75 00 6D 00 65 00 6E 00 74 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
    	$ole at 0 and $assemblylocation and $assemblyname and ($word or $excel or $powerpoint)
}

rule zip_vsto {
	strings:
	    $zip = { 50 4B 03 04 }
        $assemblylocation = "docProps/custom.xml"
        $assemblyname = "vstoDataStore/"
        $word = "word/document.xml"
        $excel = "xl/workbook.xml"
        $powerpoint = "ppt/presentation.xml"
	condition:
    	$zip at 0 and $assemblylocation and $assemblyname and ($word or $excel or $powerpoint)
}

rule ole_vsto_metadata {
	strings:
	    $ole = { D0 CF 11 E0 }
        $assemblylocation = { 12 00 00 00 5F 41 73 73 65 6D 62 6C 79 4C 6F 63 61 74 69 6F 6E }
        $assemblyname = { 0E 00 00 00 5F 41 73 73 65 6D 62 6C 79 4E 61 6D 65 }
        $metadata =       { 02 00 00 00 02 D5 CD D5 9C 2E 1B 10 93 97 08 00 2B 2C F9 AE ?? ?? ?? ?? 05 D5 CD D5 9C 2E 1B 10 93 97 08 00 2B 2C F9 AE }
	condition:
    	$ole at 0 and $assemblylocation and $assemblyname and $metadata
}

rule zip_vsto_metadata {
	strings:
	    $zip = { 50 4B 03 04 }
        $customdocprops = "docProps/custom.xml"
        $assemblylocation = { 6E 61 6D 65 3D 22 5F 41 73 73 65 6D 62 6C 79 4C 6F 63 61 74 69 6F 6E 22 }
        $assemblyname = { 6E 61 6D 65 3D 22 5F 41 73 73 65 6D 62 6C 79 4E 61 6D 65 22 }
	condition:
    	$zip at 0 and $customdocprops and $assemblylocation and $assemblyname
}

rule zip_vsto_metadata_http {
	strings:
	    $zip = { 50 4B 03 04 }
        $customdocprops = "docProps/custom.xml"
        $assemblylocation = { 6E 61 6D 65 3D 22 5F 41 73 73 65 6D 62 6C 79 4C 6F 63 61 74 69 6F 6E 22 }
        $assemblyname = { 6E 61 6D 65 3D 22 5F 41 73 73 65 6D 62 6C 79 4E 61 6D 65 22 }
        $http = "<vt:lpwstr>http"
	condition:
    	$zip at 0 and $customdocprops and $assemblylocation and $assemblyname and $http
}


rule zip_custom_date {
	strings:
	    $zip = { 50 4B 03 04 }
        $customdocpropsanydate =     { 50 4B 03 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 00 ?? ?? 64 6F 63 50 72 6F 70 73 2F 63 75 73 74 6F 6D 2E 78 6D 6C }
        $customdocpropsdefaultdate = { 50 4B 03 04 ?? ?? ?? ?? ?? ?? 00 00 21 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 00 ?? ?? 64 6F 63 50 72 6F 70 73 2F 63 75 73 74 6F 6D 2E 78 6D 6C }
        $coredocpropsdefaultdate =   { 50 4B 03 04 ?? ?? ?? ?? ?? ?? 00 00 21 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 00 ?? ?? 64 6F 63 50 72 6F 70 73 2F 63 6F 72 65 2E 78 6D 6C }

	condition:
    	$zip at 0 and $customdocpropsanydate and not $customdocpropsdefaultdate and $coredocpropsdefaultdate
}
