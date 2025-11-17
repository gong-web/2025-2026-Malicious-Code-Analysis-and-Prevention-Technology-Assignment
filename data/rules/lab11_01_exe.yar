/*
    YARA-X Rule for Lab11-01.exe
    Chapter: Chapter 11
    Sample: Lab11-01.exe
    Malware Type: Registry Persistence
    
    Description: Detects Lab11-01.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB11_01_EXE
{
    meta:
        description = "Detects Lab11-01.exe from Practical Malware Analysis"
        chapter = "Chapter 11"
        sample = "Lab11-01.exe"
        malware_type = "Registry Persistence"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "WlxDisconnectNotify"
        $net2 = "WlxReconnectNotify"
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "ADVAPI32.dll" nocase
        $dll4 = "USER32.dll" nocase
        $proc1 = "TerminateProcess"
        $file1 = "ReadFile"
        $file2 = "WriteFile"
        $file3 = "CreateFileA"
        $reg_api1 = "RegSetValueExW"
        $reg_api2 = "RegCreateKeyExA"
        $reg_api3 = "RegSetValueExA"
        $reg_api4 = "RegCreateKeyW"
        $reg_key1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $reg_key2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $import1 = "LoadLibraryW"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "MSVCRT.dll" nocase
        $susp2 = "\\msgina32.dll" nocase
        $susp3 = "WlxActivateUserShell" nocase
        $susp4 = "user32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            1 of ($proc*)
        ) and (
            1 of ($file*) or (1 of ($reg_api*) or 1 of ($reg_key*)) or 1 of ($import*) or 1 of ($susp*)
        )
}
