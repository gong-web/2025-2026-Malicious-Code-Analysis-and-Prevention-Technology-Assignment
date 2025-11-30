/*
    YARA-X Rule for Lab01-04.exe
    Chapter: Chapter 1
    Sample: Lab01-04.exe
    Malware Type: Process Injector
    
    Description: Detects Lab01-04.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB01_04_EXE
{
    meta:
        description = "Detects Lab01-04.exe from Practical Malware Analysis"
        chapter = "Chapter 1"
        sample = "Lab01-04.exe"
        malware_type = "Process Injector"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "URLDownloadToFileA"
        $dll1 = "KERNEL32.dll" nocase
        $dll2 = "ADVAPI32.dll" nocase
        $dll3 = "urlmon.dll" nocase
        $proc1 = "CreateRemoteThread"
        $proc2 = "OpenProcessToken"
        $proc3 = "OpenProcess"
        $file1 = "MoveFileA"
        $file2 = "WriteFile"
        $file3 = "GetTempPathA"
        $file4 = "CreateFileA"
        $import1 = "GetModuleHandleA"
        $import2 = "GetProcAddress"
        $import3 = "LoadLibraryA"
        $susp1 = "\\system32\\wupdmgr.exe" nocase
        $susp2 = "MSVCRT.dll" nocase
        $susp3 = "\\winup.exe" nocase
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
