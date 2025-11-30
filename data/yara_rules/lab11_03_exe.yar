/*
    YARA-X Rule for Lab11-03.exe
    Chapter: Chapter 11
    Sample: Lab11-03.exe
    Malware Type: Malware Sample
    
    Description: Detects Lab11-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB11_03_EXE
{
    meta:
        description = "Detects Lab11-03.exe from Practical Malware Analysis"
        chapter = "Chapter 11"
        sample = "Lab11-03.exe"
        malware_type = "Malware Sample"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $proc1 = "TerminateProcess"
        $proc2 = "CreateProcessA"
        $file1 = "CreateFileMappingA"
        $file2 = "CopyFileA"
        $file3 = "WriteFile"
        $file4 = "CreateFileA"
        $import1 = "GetModuleHandleA"
        $import2 = "VirtualAlloc"
        $import3 = "GetProcAddress"
        $import4 = "LoadLibraryA"
        $susp1 = "cmd.exe" nocase
        $susp2 = "cmd.exe" nocase
        $susp3 = "cisvc.exe" nocase
        $susp4 = ".exe" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($dll*) or
            2 of ($proc*) or
            1 of ($file*)
        ) and (
            1 of ($import*) or 1 of ($susp*)
        )
}
