/*
    YARA-X Rule for Lab14-01.exe
    Chapter: Chapter 14
    Sample: Lab14-01.exe
    Malware Type: Network Malware
    
    Description: Detects Lab14-01.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB14_01_EXE
{
    meta:
        description = "Detects Lab14-01.exe from Practical Malware Analysis"
        chapter = "Chapter 14"
        sample = "Lab14-01.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "URLDownloadToCacheFileA"
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "ADVAPI32.dll" nocase
        $dll4 = "urlmon.dll" nocase
        $proc1 = "TerminateProcess"
        $proc2 = "CreateProcessA"
        $file1 = "WriteFile"
        $import1 = "Sleep"
        $import2 = "VirtualAlloc"
        $import3 = "GetProcAddress"
        $import4 = "LoadLibraryA"
        $susp1 = "user32.dll" nocase
        $susp2 = "KERNEL32.dll" nocase
        $susp3 = "ADVAPI32.dll" nocase
        $susp4 = "http://www.practicalmalwareanalysis.com/%s/%c.png" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            2 of ($proc*)
        ) and (
            1 of ($file*) or 1 of ($import*) or 1 of ($susp*)
        )
}