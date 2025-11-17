rule Email_Generic_PHP_Mailer_Script
{
  meta:
		Author = "Tyler <@InfoSecTyler>"
		Description ="Generic rule to identify phishing emails"

  strings:
    $eml="Introduction"

  condition:
    $eml
}
