rule witcafecafe 
{
	meta:
		author = "Tyron Howard"
		discription = "This is a test rule to flag on a certain image cached from on CDN for witcafe.com. "
		date = "9.4.2019"
	strings:
		$a = {ff d8 ff e0 00 10 4a 46 49 46} // File Signature
		$b = {02 2e 03 97} // File Size Signature
		$c = {32 42 15 21 23 52 62 16 24 31 33 72} // Image Drawing Signature
	condition:
		$a at 0x0 and $b at 0xa3 and $c at 0xf4
}
