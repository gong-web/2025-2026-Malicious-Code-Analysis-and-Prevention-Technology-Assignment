/*
    YARA-X Rule for Lab17-01.exe
    Chapter: Chapter 17
    Sample: Lab17-01.exe
    Malware Type: Service/Backdoor
    
    Description: Detects Lab17-01.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB17_01_EXE
{
    meta:
        description = "Detects Lab17-01.exe from Practical Malware Analysis"
        chapter = "Chapter 17"
        sample = "Lab17-01.exe"
        malware_type = "Service/Backdoor"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "InternetOpenA"
        $net2 = "InternetOpenUrlA"
        $dll1 = "WININET.dll" nocase
        $dll2 = "user32.dll" nocase
        $dll3 = "KERNEL32.dll" nocase
        $dll4 = "ADVAPI32.dll" nocase
        $proc1 = "ShellExecuteA"
        $proc2 = "TerminateProcess"
        $file1 = "WriteFile"
        $svc1 = "CreateServiceA"
        $svc2 = "OpenSCManagerA"
        $import1 = "GetModuleHandleA"
        $import2 = "VirtualAlloc"
        $import3 = "GetProcAddress"
        $import4 = "LoadLibraryA"
        $susp1 = "cmd.exe" nocase
        $susp2 = "cmd.exe" nocase
        $susp3 = "WININET.dll" nocase
        $susp4 = "user32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            2 of ($proc*)
        ) and (
            1 of ($file*) or 1 of ($svc*) or 1 of ($import*) or 1 of ($susp*)
        )
}
