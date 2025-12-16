/*
    YARA-X Rule for Lab06-01.exe
    Chapter: Chapter 6
    Sample: Lab06-01.exe
    Malware Type: Network Malware
    
    Description: Detects Lab06-01.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB06_01_EXE
{
    meta:
        description = "Detects Lab06-01.exe from Practical Malware Analysis"
        chapter = "Chapter 6"
        sample = "Lab06-01.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "Success: Internet Connection"
        $net2 = "InternetGetConnectedState"
        $dll1 = "WININET.dll" nocase
        $dll2 = "user32.dll" nocase
        $dll3 = "KERNEL32.dll" nocase
        $proc1 = "TerminateProcess"
        $file1 = "WriteFile"
        $import1 = "GetModuleHandleA"
        $import2 = "VirtualAlloc"
        $import3 = "GetProcAddress"
        $import4 = "LoadLibraryA"
        $susp1 = "WININET.dll" nocase
        $susp2 = "user32.dll" nocase
        $susp3 = "KERNEL32.dll" nocase
        
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