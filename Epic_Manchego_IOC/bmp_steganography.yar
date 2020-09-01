import "dotnet"

rule DOTNET_BMP_Embedded_Settings : EpicManchego
{
    meta:
        description = "Identifies settings embedded inside a BMP resource"
        author = "NVISO (Maxime @0xThiebaut)"
        date = "2020-08-30"
        reference = "https://blog.nviso.eu/2020/09/01/epic-manchego-atypical-maldoc-delivery-brings-flurry-of-infostealers/"
        tlp = "WHITE"
        
        hash1 = "9D3DF770B6DCD5BEB650A097A597BB70C49DDE306517BBC731812BF18A806719"
        hash2 = "BCFC34CBA923F98AAEF2289267664A3637C46B20D409A86E2EEEFEB71F3CC4BB"
        hash3 = "0CCEAAFD17DF02AAA546D427453894E81847CF2056A136BD3C0A7FD5320F379C"
        hash4 = "7D057DD5E8AA5E5562CE9598B6C606009AC7EC9A776EDAF2D9AB2BCBA347F00D"
        hash5 = "82695734165A830A7EC7F6030E27A9F3996DF3A1C5A66FF3FEFD41D2EF360B6F"

    strings:
        $bmp = {42 4D}
        $key1 = "mtvZcVWEPsEoZtU"
        $key2 = "qcxpujZazqPECJy"
        $key3 = "byrxoijRrNcoNgu"
        $key4 = "HnAKuxDTInPytwQ"
        $key5 = "iEupkzVawcoHato"
        $key6 = "vDwFwUoVLXqOoga"
        $key7 = "TlTtbvmhyGKLUtf"
        $key8 = "xfnzyNZlJtFifWW"
        $key9 = "BUEcNMaVQCHwkPj"
        $key10 = "vjlchNzirgSxjSC"
        $key11 = "EpkVBztLXeSpKwe"
        $key12 = "gLoZAUILJbMTRzx"
        $key13 = "dqlSSjORBJtbYok"
        $key14 = "JyOFtnLkpGcbMny"
        $key15 = "PXcli.0.XdHg"
        $key16 = "PXcli.0.QdSmo"
        $key17 = "PXcli.0.gvSLtt"
        $key18 = "PXcli.0.gGmd"

    condition:
        uint16(0) == 0x5A4D and filesize < 2048KB and for any i in (1..dotnet.number_of_resources) : (      // Look for a .NET executable with a resource..
            for any j in (1..#bmp) : (                                                                      // Containing a BMP image..
                @bmp[j] >= dotnet.resources[i].offset and                                                   // Whose start is within the resource..
                @bmp[j]+uint32(@bmp[j]+0x02) <= dotnet.resources[i].offset+dotnet.resources[i].length and   // And whose end is within the same resource..
                for 3 of ($key*): ($ in (@bmp[j]+uint32(@bmp[j]+0x0E)..@bmp[j]+uint32(@bmp[j]+0x02)))       // Where 3 of the keys are contained within the BMP.
            )
        )
}

rule DOTNET_BMP_Embedded_PE : EpicManchego
{
    meta:
        description = "Identifies a PE embedded inside a BMP resource"
        author = "NVISO (Maxime @0xThiebaut)"
        date = "2020-08-30"
        reference = "https://blog.nviso.eu/2020/09/01/epic-manchego-atypical-maldoc-delivery-brings-flurry-of-infostealers/"
        tlp = "WHITE"
        
        hash1 = "9D3DF770B6DCD5BEB650A097A597BB70C49DDE306517BBC731812BF18A806719"
        hash2 = "BCFC34CBA923F98AAEF2289267664A3637C46B20D409A86E2EEEFEB71F3CC4BB"
        hash3 = "0CCEAAFD17DF02AAA546D427453894E81847CF2056A136BD3C0A7FD5320F379C"
        hash4 = "7D057DD5E8AA5E5562CE9598B6C606009AC7EC9A776EDAF2D9AB2BCBA347F00D"
        hash5 = "82695734165A830A7EC7F6030E27A9F3996DF3A1C5A66FF3FEFD41D2EF360B6F"

    strings:
        // Fragmented strings split across the BMP bitmap sections
        $bmp = {42 4D}
        $pe1 = "PE"
        $pe2 = "MZ"
        $pe3 = ".text"
        $pe4 = ".reloc"
        $pe5 = ".rsrc"
        $pe6 = "This program"
        $pe7 = "program cannot"
        $pe8 = "cannot be run"
        $pe9 = "run in DOS"
        $pe10 = "DOS mode"
        $pe11 = "program must"
        $pe12 = "must be run"
        $pe13 = "run under"
        $pe14 = "under Win32"
        $pe15 = "DATA"
        $pe16 = "CODE"

    condition:
            uint16(0) == 0x5A4D and filesize < 2048KB and for any i in (1..dotnet.number_of_resources) : (      // Look for a .NET executable with a resource..
                for any j in (1..#bmp) : (                                                                      // Containing a BMP image..
                    @bmp[j] >= dotnet.resources[i].offset and                                                   // Whose start is within the resource..
                    @bmp[j]+uint32(@bmp[j]+0x02) <= dotnet.resources[i].offset+dotnet.resources[i].length and   // And whose end is within the same resource..
                    for 3 of ($pe*): ($ in (@bmp[j]+uint32(@bmp[j]+0x0E)..@bmp[j]+uint32(@bmp[j]+0x02)))        // Where 3 of the PE indicators are contained within the BMP.
                )
            )
}
