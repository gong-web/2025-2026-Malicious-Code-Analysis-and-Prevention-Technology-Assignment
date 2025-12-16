/*
    YARA-X Rule for Lab09-02.exe
    Chapter: Chapter 9
    Sample: Lab09-02.exe
    Malware Type: Network Malware
    
    Description: Detects Lab09-02.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB09_02_EXE
{
    meta:
        description = "Detects Lab09-02.exe from Practical Malware Analysis"
        chapter = "Chapter 9"
        sample = "Lab09-02.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "WSASocketA"
        $net2 = "WS2_32.dll" nocase
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "WS2_32.dll" nocase
        $proc1 = "TerminateProcess"
        $proc2 = "CreateProcessA"
        $file1 = "WriteFile"
        $import1 = "Sleep"
        $import2 = "VirtualAlloc"
        $import3 = "GetProcAddress"
        $import4 = "LoadLibraryA"
        $susp1 = "user32.dll" nocase
        $susp2 = "KERNEL32.dll" nocase
        $susp3 = "WS2_32.dll" nocase
        
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