rule ZLoader_fake_MSI_Dropper_Aug_2021_TIM
{
meta:
       author = "Antonio Pirozzi@Sentinelone"
       description = "rule to identify the fake teamviewer/zoom msi installer related to the ZLoaderAug 2021 ‘Tim‘ campaign"
         created = "29 Aug 2021"
         sample = "a0c97cd4608d62e2124087ecd668c73ec3136c91"
strings:
                 $serial={0e ff d7 99 ba 5f 84 c8 24 4f 39 4d 88 1f 40 a3}
                 $signer = "Flyintellect Inc."
condition:
          uint16(0) == 0xcfd0 and ($serial) and ($signer)
}
