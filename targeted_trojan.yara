rule tageted_trojan_stage3 {
    meta:
      Author = "Tyron Howard"
      Engine = "VT"
      Description = "Tracking 'new-age' trojan that is a javascript file in a wild"
      Created = "5.6.2019"
      Referance = ""
    strings:
        $s1 = /var\s[a-zA-Z][0-9]\_[0-9]{1,}/
        $s2 = /eval\([a-zA-Z][0-9]\_[0-9]{1,}/
        $s3 = /\.concat\(/
        $s4 = /\(\"TV[a-zA-Z]{1,}\//
        $s5 = /\/[a-zA-Z0-9]{1,}\=\"\)/
    condition:
        all of them and (file_type contains "js" or file_type contains "script")
}
