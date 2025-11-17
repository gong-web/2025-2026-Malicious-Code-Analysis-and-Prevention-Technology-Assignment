rule test_inactive_rule
{
    meta:
        description = "Inactive test rule"
        author = "Test User"
        date = "2025-11-12"
    
    strings:
        $test = "inactive"
    
    condition:
        $test
}
