/*
    YARA-X Rule for Lab09-03.exe
    Chapter: Chapter 9
    Sample: Lab09-03.exe
    Malware Type: Malware Sample
    
    Description: Detects Lab09-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB09_03_EXE
{
    meta:
        description = "Detects Lab09-03.exe from Practical Malware Analysis"
        chapter = "Chapter 9"
        sample = "Lab09-03.exe"
        malware_type = "Malware Sample"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $proc1 = "TerminateProcess"
        $file1 = "WriteFile"
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "NETAPI32.dll" nocase
        $susp2 = "DLL3.dll" nocase
        $susp3 = "user32.dll" nocase
        $susp4 = "KERNEL32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($dll*) or
            1 of ($proc*) or
            1 of ($file*)
        ) and (
            1 of ($import*) or 1 of ($susp*)
        )
}
