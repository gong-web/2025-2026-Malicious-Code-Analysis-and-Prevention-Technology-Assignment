/*
    YARA-X Rule for Lab18-01.exe
    Chapter: Chapter 18
    Sample: Lab18-01.exe
    Malware Type: Network Malware
    
    Description: Detects Lab18-01.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB18_01_EXE
{
    meta:
        description = "Detects Lab18-01.exe from Practical Malware Analysis"
        chapter = "Chapter 18"
        sample = "Lab18-01.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "URLDownloadToCacheFileA"
        $dll1 = "ADVAPI32.dll" nocase
        $dll2 = "KERNEL32.DLL" nocase
        $dll3 = "urlmon.dll" nocase
        $import1 = "VirtualProtect"
        $import2 = "VirtualAlloc"
        $import3 = "GetProcAddress"
        $import4 = "LoadLibraryA"
        $susp1 = "ADVAPI32.dll" nocase
        $susp2 = "KERNEL32.DLL" nocase
        $susp3 = "urlmon.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            1 of ($import*)
        ) and (
            1 of ($susp*)
        )
}