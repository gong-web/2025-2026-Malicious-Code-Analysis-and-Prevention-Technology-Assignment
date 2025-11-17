/*
    YARA-X Rule for Lab01-03.exe
    Chapter: Chapter 1
    Sample: Lab01-03.exe
    Malware Type: Malware Sample
    
    Description: Detects Lab01-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB01_03_EXE
{
    meta:
        description = "Detects Lab01-03.exe from Practical Malware Analysis"
        chapter = "Chapter 1"
        sample = "Lab01-03.exe"
        malware_type = "Malware Sample"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "KERNEL32.dll" nocase
        $import1 = "LoadLibraryA"
        $import2 = "GetProcAddress"
        $susp1 = "KERNEL32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        1 of ($dll*) and 1 of ($import*) and 1 of ($susp*)
}
