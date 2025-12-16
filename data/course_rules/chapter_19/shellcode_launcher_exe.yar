/*
    YARA-X Rule for shellcode_launcher.exe
    Chapter: Chapter 19
    Sample: shellcode_launcher.exe
    Malware Type: Shellcode Execution Tool
    
    Description: Detects shellcode_launcher.exe - a tool for loading and executing shellcode
    
    This is a utility program used in Chapter 19 for shellcode analysis exercises.
    It reads shellcode from a file and executes it in memory.
    
    Key features:
    - Reads shellcode from file
    - Allocates executable memory
    - Supports breakpoints before execution
    - Can set registers before jumping to shellcode
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_Shellcode_Launcher_EXE
{
    meta:
        description = "Detects shellcode_launcher.exe - shellcode execution utility"
        chapter = "Chapter 19"
        sample = "shellcode_launcher.exe"
        malware_type = "Shellcode Execution Tool"
        severity = "medium"
        
    strings:
        // Specific strings from the launcher
        $str1 = "shellcode buffer" nocase
        $str2 = "offset" nocase
        $str3 = "breakpoint" nocase
        
        // Key APIs for shellcode loading
        $api1 = "VirtualAlloc"
        $api2 = "ReadFile"
        $api3 = "CreateFileA"
        $api4 = "LoadLibraryA"
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            // Specific string pattern
            (2 of ($str*)) or
            // API pattern
            (3 of ($api*)) or
            // Combined pattern
            ($str1 and 2 of ($api*))
        )
}