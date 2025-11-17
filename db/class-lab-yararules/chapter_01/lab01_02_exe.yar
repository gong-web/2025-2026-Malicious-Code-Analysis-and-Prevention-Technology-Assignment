/*
    YARA-X Rule for Lab01-02.exe
    Chapter: Chapter 1
    Sample: Lab01-02.exe
    Malware Type: Service/Backdoor
    
    Description: Detects Lab01-02.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB01_02_EXE
{
    meta:
        description = "Detects Lab01-02.exe from Practical Malware Analysis"
        chapter = "Chapter 1"
        sample = "Lab01-02.exe"
        malware_type = "Service/Backdoor"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "InternetOpenA"
        $dll1 = "ADVAPI32.dll" nocase
        $dll2 = "KERNEL32.DLL" nocase
        $dll3 = "WININET.dll" nocase
        $svc1 = "CreateServiceA"
        $import1 = "VirtualProtect"
        $import2 = "LoadLibraryA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "MSVCRT.dll" nocase
        $susp2 = "http://w" nocase
        $susp3 = "ADVAPI32.dll" nocase
        $susp4 = "KERNEL32.DLL" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            1 of ($svc*)
        ) and (
            1 of ($import*) or 1 of ($susp*)
        )
}
