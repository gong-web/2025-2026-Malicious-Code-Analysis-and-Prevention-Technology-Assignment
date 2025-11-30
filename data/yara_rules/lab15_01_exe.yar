/*
    YARA-X Rule for Lab15-01.exe
    Chapter: Chapter 15
    Sample: Lab15-01.exe
    Malware Type: Malware Sample
    
    Description: Detects Lab15-01.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB15_01_EXE
{
    meta:
        description = "Detects Lab15-01.exe from Practical Malware Analysis"
        chapter = "Chapter 15"
        sample = "Lab15-01.exe"
        malware_type = "Malware Sample"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $susp1 = "MSVCRT.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        1 of ($susp*)
}
