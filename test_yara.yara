rule found_malicious {
	meta:
		description = "my first yara rule"
		author = "Bala"
		dat = "2025/04/02"
	strings:
		$a = /ma?icious\d+/
		$b = "darling!"
		$_pvt = "ENCRYPTED" ascii nocase private
    condition:
		$a and $b
}
