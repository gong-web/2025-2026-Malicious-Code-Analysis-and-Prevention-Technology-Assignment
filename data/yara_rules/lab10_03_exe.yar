/*
    YARA-X Rule for Lab10-03.exe
    Chapter: Chapter 10
    Sample: Lab10-03.exe
    Malware Type: Service/Backdoor
    
    Description: Detects Lab10-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB10_03_EXE
{
    meta:
        description = "Detects Lab10-03.exe from Practical Malware Analysis"
        chapter = "Chapter 10"
        sample = "Lab10-03.exe"
        malware_type = "Service/Backdoor"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "ADVAPI32.dll" nocase
        $proc1 = "TerminateProcess"
        $file1 = "WriteFile"
        $file2 = "CreateFileA"
        $svc1 = "StartServiceA"
        $svc2 = "CreateServiceA"
        $svc3 = "OpenSCManagerA"
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "OLEAUT32.dll" nocase
        $susp2 = "http://www.malwareanalysisbook.com/ad.html" nocase
        $susp3 = "user32.dll" nocase
        $susp4 = "KERNEL32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($dll*) or
            1 of ($proc*) or
            1 of ($file*)
        ) and (
            1 of ($svc*) or 1 of ($import*) or 1 of ($susp*)
        )
}