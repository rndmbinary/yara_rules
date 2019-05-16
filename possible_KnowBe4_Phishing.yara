rule possible_knowbe4_phishing1
{
    meta:
    	hash = "77a1 f412 8401 bb4c 2f95 5825 2866 2ff2"
    strings:
      	$m1 = {50 4b 03 04 0a 00}
	$s1 = "xl/worksheets/sheet1.xmlUT" ascii
        $s2 = "xl/worksheets/sheet2.xmlUT" ascii
        $s3 = "xl/worksheets/sheet3.xmlUT" ascii
        $s4 = /xl\/media\/image[0-9]\.jpgUT/ ascii
        $s5 = /invoice\_[A-Za-z]\-[0-9]{1,}/
    condition:
        all of them
}
