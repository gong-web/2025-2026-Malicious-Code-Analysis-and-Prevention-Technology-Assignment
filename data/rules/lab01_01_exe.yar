/*
    YARA-X Rule for Lab01-01.exe
    Chapter: Chapter 1
    Sample: Lab01-01.exe
    Malware Type: Malware Sample
    
    Description: Detects Lab01-01.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB01_01_EXE
{
    meta:
        description = "Detects Lab01-01.exe from Practical Malware Analysis"
        chapter = "Chapter 1"
        sample = "Lab01-01.exe"
        malware_type = "Malware Sample"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "C:\\Windows\\System32\\Kernel32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "kernel32.dll" nocase
        $dll4 = "Kernel32."
        $file1 = "CopyFileA"
        $file2 = "CreateFileMappingA"
        $file3 = "FindFirstFileA"
        $file4 = "CreateFileA"
        $susp1 = "C:\\Windows\\System32\\Kernel32.dll" nocase
        $susp2 = "MSVCRT.dll" nocase
        $susp3 = "C:\\windows\\system32\\kerne132.dll" nocase
        $susp4 = "kerne132.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        1 of ($dll*) and 1 of ($file*) and 1 of ($susp*)
}
