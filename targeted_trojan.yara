rule tageted_trojan_stage3_AT21271 {
    meta:
      Author = "Tyron Howard"
      Engine = "VT"
      Description = "Tacking 'new-age' trojan that is a javascript file in a wild"
      Created = "5.6.2019"
      Referance = "849FD4884996E41D36BC42E74726C7CE"
    strings:
        $s1 = /var\s[a-zA-Z][0-9]\_[0-9]{1,}/
        $s2 = /eval\([a-zA-Z][0-9]\_[0-9]{1,}/
        $s3 = /\.concat\(/
        $s4 = /\(\"TV[a-zA-Z]{1,}\//
        $s5 = /\/[a-zA-Z0-9]{1,}\=\"\)/
    condition:
        all of them and (file_type contains "js" or file_type contains "script")
}

rule targeted_trojan_stage4_AT21271 {
    meta:
      Author = "Tyron Howard"
      Engine = "VT"
      Description = "Tacking 'new-age' trojan that is a exe file in a wild"
      Created = "5.6.2019"
      Referance = "F07607EF2E4FC1B182C10349D2844EED"
    condition:
      md5 contains "F07607EF2E4FC1B182C10349D2844EED"
}
