/*
    YARA-X Rule for Lab20-03.exe
    Chapter: Chapter 20
    Sample: Lab20-03.exe
    Malware Type: Network Malware
    
    Description: Detects Lab20-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB20_03_EXE
{
    meta:
        description = "Detects Lab20-03.exe from Practical Malware Analysis"
        chapter = "Chapter 20"
        sample = "Lab20-03.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "Accept: text/html"
        $net2 = ".?AUConnectError@@"
        $net3 = ".?AUSocketError@@"
        $net4 = "Connection: close"
        $dll1 = "ADVAPI32.dll" nocase
        $dll2 = "user32.dll" nocase
        $dll3 = "KERNEL32.dll" nocase
        $dll4 = "WS2_32.dll" nocase
        $proc1 = "TerminateProcess"
        $proc2 = "CreateProcessA"
        $file1 = "ReadFile"
        $file2 = "CreateFileA"
        $file3 = "WriteFile"
        $import1 = "Sleep"
        $import2 = "LoadLibraryA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "ADVAPI32.dll" nocase
        $susp2 = "user32.dll" nocase
        $susp3 = "KERNEL32.dll" nocase
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
