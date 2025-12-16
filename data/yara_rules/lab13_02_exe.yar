/*
    YARA-X Rule for Lab13-02.exe
    Chapter: Chapter 13
    Sample: Lab13-02.exe
    Malware Type: Malware Sample
    
    Description: Detects Lab13-02.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB13_02_EXE
{
    meta:
        description = "Detects Lab13-02.exe from Practical Malware Analysis"
        chapter = "Chapter 13"
        sample = "Lab13-02.exe"
        malware_type = "Malware Sample"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "USER32.dll" nocase
        $proc1 = "TerminateProcess"
        $file1 = "WriteFile"
        $file2 = "CreateFileA"
        $import1 = "Sleep"
        $import2 = "VirtualAlloc"
        $import3 = "GetProcAddress"
        $import4 = "LoadLibraryA"
        $susp1 = "user32.dll" nocase
        $susp2 = "GDI32.dll" nocase
        $susp3 = "KERNEL32.dll" nocase
        $susp4 = "USER32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($dll*) or
            1 of ($proc*) or
            1 of ($file*)
        ) and (
            1 of ($import*) or 1 of ($susp*)
        )
}