/*
    YARA-X Rule for Lab07-03.dll
    Chapter: Chapter 7
    Sample: Lab07-03.dll
    Malware Type: Network Malware
    
    Description: Detects Lab07-03.dll from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB07_03_DLL
{
    meta:
        description = "Detects Lab07-03.dll from Practical Malware Analysis"
        chapter = "Chapter 7"
        sample = "Lab07-03.dll"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "WS2_32.dll" nocase
        $dll1 = "WS2_32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $proc1 = "CreateProcessA"
        $import1 = "Sleep"
        $import2 = "sleep"
        $susp1 = "MSVCRT.dll" nocase
        $susp2 = "WS2_32.dll" nocase
        $susp3 = "KERNEL32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) != 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            1 of ($proc*)
        ) and (
            1 of ($import*) or 1 of ($susp*)
        )
}