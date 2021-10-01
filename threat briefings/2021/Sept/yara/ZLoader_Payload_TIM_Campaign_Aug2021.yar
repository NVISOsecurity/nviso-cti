import "pe"
rule ZLoader_Payload_TIM_Campaign_Aug2021
{
   meta:
       author = "Antonio Pirozzi@Sentinelone"
       description = "rule to detect the main ZLoader payload related to the Aug 2021 'Tim' campaign"
         created = "29 Aug 2021"
sample = "dc945e57be6bdd3cc4894d6cff7dd90a76f6c416"
   strings:


$signature1="Dgnet" ascii wide
$signature2="POP3[110], POP2[109], SMTP[25], IMAP[143]" ascii wide


condition:
uint16(0) == 0x5a4d and pe.exports("DllCanUnloadNow") and
pe.exports("DllUnregisterServer") and
pe.exports("DllRegisterServer") and
pe.exports("DllGetClassObject") and
pe.number_of_resources==59 and filesize>400000 and all of them
}
