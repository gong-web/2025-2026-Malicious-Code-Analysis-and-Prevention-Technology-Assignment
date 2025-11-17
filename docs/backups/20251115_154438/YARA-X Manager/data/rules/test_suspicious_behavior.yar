rule test_suspicious_behavior
{
    meta:
        description = "Test rule for suspicious behavior"
        author = "Test User"
        date = "2025-11-12"
    
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $cmd3 = "suspicious" nocase
    
    condition:
        any of them
}
