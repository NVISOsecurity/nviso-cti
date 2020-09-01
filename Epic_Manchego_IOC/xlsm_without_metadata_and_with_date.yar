rule xlsm_without_metadata_and_with_date {
	meta:
		description = "Identifies .xlsm files created with EPPlus"
		author = "NVISO (Didier Stevens)"
		date = "2020-07-12"
		reference = "https://blog.nviso.eu/2020/09/01/epic-manchego-atypical-maldoc-delivery-brings-flurry-of-infostealers/"
		tlp = "White"
                strings:
                                $opc = "[Content_Types].xml"
                                $ooxml = "xl/workbook.xml"
                                $vba = "xl/vbaProject.bin"           
                                $meta1 = "docProps/core.xml"
                                $meta2 = "docProps/app.xml"
                                $timestamp = {50 4B 03 04 ?? ?? ?? ?? ?? ?? 00 00 21 00}
                condition:
                                uint32be(0) == 0x504B0304 and ($opc and $ooxml and $vba) 
and not (any of ($meta*) and $timestamp)
}
