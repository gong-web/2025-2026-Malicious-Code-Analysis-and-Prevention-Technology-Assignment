/*
    YARA-X Rule for Lab20-01.exe
    Chapter: Chapter 20
    Sample: Lab20-01.exe
    Malware Type: Network Malware
    
    Description: Detects Lab20-01.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB20_01_EXE
{
    meta:
        description = "Detects Lab20-01.exe from Practical Malware Analysis"
        chapter = "Chapter 20"
        sample = "Lab20-01.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "URLDownloadToFileA"
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "urlmon.dll" nocase
        $proc1 = "TerminateProcess"
        $file1 = "WriteFile"
        $import1 = "GetModuleHandleA"
        $import2 = "VirtualAlloc"
        $import3 = "GetProcAddress"
        $import4 = "LoadLibraryA"
        $susp1 = "user32.dll" nocase
        $susp2 = "http://www.practicalmalwareanalysis.com/cpp.html" nocase
        $susp3 = "KERNEL32.dll" nocase
        $susp4 = "empdownload.exe" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            1 of ($proc*)
        ) and (
            1 of ($file*) or 1 of ($import*) or 1 of ($susp*)
        )
}
