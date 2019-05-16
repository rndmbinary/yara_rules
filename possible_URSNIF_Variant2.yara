rule Possible_URSNIF_Variant2
{
        meta:
                author = "Tyron Howard"
                date = "19 April 2019"
                description = "This is a test rule to discover Ursnif in the wild - ursnif_vba_strings"
                md5 = "4422e43bc462c62fcc00533fcee9945a"
        strings:
        				$m1 = {D0 CF 11 E0 A1 B1 1A E1}
                $m2 = {50 4B 05 (02|08)}
                $s1 = "autoopen" ascii nocase fullword
                $s2 = /Tahoma[a-zA-Z0-9]{2}/ ascii nocase
                $s3 = "PasswordChar" ascii nocase
                $s4 = "JAB" ascii
                $s5 = "AKQA=" ascii
                $s6 = /pow(o|)/ ascii nocase
                $s7 = "ershell" ascii nocase
        condition:
                1 of ($m*) and 5 of ($s*)
}
