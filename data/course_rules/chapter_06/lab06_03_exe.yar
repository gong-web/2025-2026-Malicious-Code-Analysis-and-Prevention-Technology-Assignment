/*
    YARA-X Rule for Lab06-03.exe
    Chapter: Chapter 6
    Sample: Lab06-03.exe
    Malware Type: Registry Persistence
    
    Description: Detects Lab06-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB06_03_EXE
{
    meta:
        description = "Detects Lab06-03.exe from Practical Malware Analysis"
        chapter = "Chapter 6"
        sample = "Lab06-03.exe"
        malware_type = "Registry Persistence"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "Success: Internet Connection"
        $net2 = "InternetOpenA"
        $net3 = "InternetOpenUrlA"
        $net4 = "InternetGetConnectedState"
        $dll1 = "WININET.dll" nocase
        $dll2 = "user32.dll" nocase
        $dll3 = "KERNEL32.dll" nocase
        $dll4 = "ADVAPI32.dll" nocase
        $proc1 = "TerminateProcess"
        $file1 = "DeleteFileA"
        $file2 = "Error 2.2: Fail to ReadFile"
        $file3 = "InternetReadFile"
        $file4 = "CopyFileA"
        $reg_api1 = "RegSetValueExA"
        $reg_api2 = "RegOpenKeyExA"
        $reg_key1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg_key2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "C:\\Temp\\cc.exe" nocase
        $susp2 = "WININET.dll" nocase
        $susp3 = "user32.dll" nocase
        $susp4 = "KERNEL32.dll" nocase
        
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
