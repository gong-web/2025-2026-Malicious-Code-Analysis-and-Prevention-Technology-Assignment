rule Email_Generic_Phishing : email
{
  meta:
		Author = "Tyler <@InfoSecTyler>"
		Description ="Generic rule to identify phishing emails"

  strings:
    $eml="center"

  condition:
    $eml
}
