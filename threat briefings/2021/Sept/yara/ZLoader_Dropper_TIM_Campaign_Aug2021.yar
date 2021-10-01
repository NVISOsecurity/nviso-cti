rule ZLoader_Dropper_TIM_Campaign_Aug2021
{   meta:       author = "Antonio Pirozzi@Sentinelone"       
		description = "rule to identify the Dropper of the ZLoader infection chain related to the Aug 2021 'Tim' campaign"   
		created = "29 Aug 2021"   
		sample = "42f1d5711e5f5e67680043ba11b16da4709cfa1e"
	strings:
		$str1="POSTRUNPROGRAM"  ascii wide
		$str2="ADMQCMD"  ascii wide
		$str3="EXTRACTOPT"  ascii wide
		$str4="PACKINSTSPACE"  ascii wide
		$str5="SHOWWINDOW"  ascii wide
		$str6="UPROMPT"  ascii wide
		$str7="USRQCMD"  ascii wide                           
		$str8="RUNPROGRAM"  ascii wide                           
		$str9="WEXTRACT.EXE"  ascii wide                           
		$str10="cmd /c tim.bat"  ascii wide nocase   
condition:
uint16(0) == 0x5a4d and all of them 
}
