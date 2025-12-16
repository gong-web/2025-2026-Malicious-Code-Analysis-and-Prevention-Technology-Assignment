/*
    YARA-X Rule for Lab12-01.dll
    Chapter: Chapter 12
    Sample: Lab12-01.dll
    Malware Type: Malware Sample
    
    Description: Detects Lab12-01.dll from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB12_01_DLL
{
    meta:
        description = "Detects Lab12-01.dll from Practical Malware Analysis"
        chapter = "Chapter 12"
        sample = "Lab12-01.dll"
        malware_type = "Malware Sample"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "USER32.dll" nocase
        $proc1 = "TerminateProcess"
        $file1 = "WriteFile"
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "user32.dll" nocase
        $susp2 = "KERNEL32.dll" nocase
        $susp3 = "USER32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) != 0 and
        (
            1 of ($dll*) or
            1 of ($proc*) or
            1 of ($file*)
        ) and (
            1 of ($import*) or 1 of ($susp*)
        )
}