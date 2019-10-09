rule ebee2a28_doc : delivery 
{
    meta:
    description = "Rule to track [redacted] malicious documents in the wild."
        author = "Tyron Howard"
        date = "10.07.2019"
        engine = "VT"
        sevartiy = "1"
        sample1 = "1334c087390fb946c894c1863dfc9f0a659f594a3d6307fb48f24c30a23e0fc0"
        sample2 = "94a09aff59c0c27d1049509032d5ba05e9285fd522eb20b033b8188e0fee4ff0"
        sample3 = "dc425e93e83fe02da9c76b56f6fd286eace282eaad6d8d497e17b3ec4059020a"
        sample4 = "8fc33ba25862fd7bff51d94941e79249" //PNG Image Found in Document"
        RetroHunt = "Successful"
        
    strings:
  	$h1 = {62 61 50 72 6f 6a 65 63 74 2e 62 69 6e ec 5a (7d|0b)}
        $s1 = "ge1" nocase
        $i1 = {89 50 4E 47 0D 0A 1A 0A} // PNG Signature
        $i2 = {49 48 44 52} // PNG IHDR Start 
        $i3 = {00 00 02 44 00 00 01 45} // PNG Width and Height
        $i4 = {0D 54 F2 62} // PNG CRC Check
        $i5 = {49 45 4E 44 AE 42 60 82} // PNG Trailer
        
    condition:
    	(($h1 at 0x1320 and $s1 and all of ($i*)) and file_type contains "document")
}

rule ebee2a28_code : delivery
{
    meta:
        description = "Rule to track [redacted] malicious documents in the wild."
        author = "Tyron Howard"
        date = "10.02.2019"
        engine = "VT"
        sevartiy = "1"
        sample1 = "1334c087390fb946c894c1863dfc9f0a659f594a3d6307fb48f24c30a23e0fc0"
        sample2 = "94a09aff59c0c27d1049509032d5ba05e9285fd522eb20b033b8188e0fee4ff0"
        sample3 = "dc425e93e83fe02da9c76b56f6fd286eace282eaad6d8d497e17b3ec4059020a"

    strings:
        $s1 = "AutoOpen()" fullword
        $s2 = "CreateObject" fullword
        $s3 = "MSXML2.ServerXMLHTTP.6.0"
        $s4 = /\.Open\s\"\w+?\"/
        $s5 = /Run(\w+?|\d+?)\(\d+?\)/
        $s6 = /wShell\s\=\sCreateObject\((\w+?|\d+?)\(\d+?\)\)/
        $s7 = /wShell\.ExpandEnvironmentStrings\(\"\%(\w+?|\d+?)\%\"\)/

    condition:
        4 of ($s*) and file_type contains "document"
}


rule ebee2a28_vba : delivery
{
    meta:
        description = "Rule to track [redacted] malicious documents in the wild."
        decription = "This inspects vbaProject.bin files for indicators"
        author = "Tyron Howard"
        date = "10.02.2019"
        engine = "VT"
        sevartiy = "1"
        sample1 = "1334c087390fb946c894c1863dfc9f0a659f594a3d6307fb48f24c30a23e0fc0"
        sample2 = "94a09aff59c0c27d1049509032d5ba05e9285fd522eb20b033b8188e0fee4ff0"
        sample3 = "dc425e93e83fe02da9c76b56f6fd286eace282eaad6d8d497e17b3ec4059020a"

    strings:
        $s1 = "AutoOpen" fullword
        $s2 = "MSXML2.ServerXMLHTTP.6.0"
        $s3 = "GET" fullword
        $s4 = "wShe" fullword
        $s5 = "Run" fullword
        $s6 = /\%temp\%/
        $s7 = "ExpandEnvironment"
        $s8 = "retu" nocase fullword
        $m1 = /\\.{1,20}(\.doc|\.docx)/

    condition:
        6 of ($s*) and $m1
}

rule ebee2a28_png : indicator
{
    meta:
        description = "Rule to track [redacted] malicious documents in the wild."
        author = "Tyron Howard"
        date = "10.07.2019"
        engine = "VT"
        sevartiy = "1"
        sample4 = "8fc33ba25862fd7bff51d94941e79249" //PNG Image Found in Document"
        RetroHunt = "Successful"
        Song = "Lupe Fiasco - Daydreamin' Feat. Jill Scott"
        
    strings:
        $i1 = {89 50 4E 47 0D 0A 1A 0A} // PNG Signature
        $i2 = {49 48 44 52} // PNG IHDR Start 
        $i3 = {00 00 02 44 00 00 01 45} // PNG Width and Height
        $i4 = {0D 54 F2 62} // PNG CRC Check
        $i5 = {49 45 4E 44 AE 42 60 82} // PNG Trailer
        
    condition:
    	all of ($i*) and file_type contains "document"
}
