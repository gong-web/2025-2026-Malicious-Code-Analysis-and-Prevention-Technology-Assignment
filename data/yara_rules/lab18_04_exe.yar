/*
    YARA-X Rule for Lab18-04.exe
    Chapter: Chapter 18
    Sample: Lab18-04.exe
    Malware Type: Service/Backdoor
    
    Description: Detects Lab18-04.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB18_04_EXE
{
    meta:
        description = "Detects Lab18-04.exe from Practical Malware Analysis"
        chapter = "Chapter 18"
        sample = "Lab18-04.exe"
        malware_type = "Service/Backdoor"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "ws2_32.dll" nocase
        $dll1 = "user32.dll" nocase
        $dll2 = "advapi32.dll" nocase
        $dll3 = "ws2_32.dll" nocase
        $dll4 = "kernel32.dll" nocase
        $proc1 = "ShellExecuteA"
        $svc1 = "OpenSCManagerA"
        $import1 = "GetModuleHandleA"
        $import2 = "LoadLibraryA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "user32.dll" nocase
        $susp2 = "advapi32.dll" nocase
        $susp3 = "ws2_32.dll" nocase
        $susp4 = "shell32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            1 of ($proc*)
        ) and (
            1 of ($svc*) or 1 of ($import*) or 1 of ($susp*)
        )
}