/*
    YARA-X Rule for Lab13-03.exe
    Chapter: Chapter 13
    Sample: Lab13-03.exe
    Malware Type: Network Malware
    
    Description: Detects Lab13-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB13_03_EXE
{
    meta:
        description = "Detects Lab13-03.exe from Practical Malware Analysis"
        chapter = "Chapter 13"
        sample = "Lab13-03.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "WSASocketA"
        $net2 = "WS2_32.dll" nocase
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "WS2_32.dll" nocase
        $dll4 = "USER32.dll" nocase
        $proc1 = "TerminateProcess"
        $proc2 = "CreateProcessA"
        $file1 = "ReadFile"
        $file2 = "WriteFile"
        $import1 = "LoadLibraryA"
        $import2 = "VirtualAlloc"
        $import3 = "GetProcAddress"
        $import4 = "GetCommandLineA"
        $susp1 = "cmd.exe" nocase
        $susp2 = "cmd.exe" nocase
        $susp3 = "user32.dll" nocase
        $susp4 = "KERNEL32.dll" nocase
        
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
