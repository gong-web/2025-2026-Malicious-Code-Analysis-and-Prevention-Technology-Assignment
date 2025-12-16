/*
    YARA-X Rule for Lab21-01.exe
    Chapter: Chapter 21
    Sample: Lab21-01.exe
    Malware Type: Network Malware
    
    Description: Detects Lab21-01.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB21_01_EXE
{
    meta:
        description = "Detects Lab21-01.exe from Practical Malware Analysis"
        chapter = "Chapter 21"
        sample = "Lab21-01.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "WSASocketA"
        $net2 = "WS2_32.dll" nocase
        $dll1 = "KERNEL32.dll" nocase
        $dll2 = "USER32.DLL" nocase
        $dll3 = "WS2_32.dll" nocase
        $proc1 = "TerminateProcess"
        $proc2 = "CreateProcessA"
        $file1 = "WriteFile"
        $import1 = "Sleep"
        $import2 = "GetModuleHandleW"
        $import3 = "LoadLibraryW"
        $import4 = "GetProcAddress"
        $susp1 = "mscoree.dll" nocase
        $susp2 = "KERNEL32.dll" nocase
        $susp3 = "USER32.DLL" nocase
        $susp4 = "WS2_32.dll" nocase
        
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
