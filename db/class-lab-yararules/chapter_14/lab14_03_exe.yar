/*
    YARA-X Rule for Lab14-03.exe
    Chapter: Chapter 14
    Sample: Lab14-03.exe
    Malware Type: Network Malware
    
    Description: Detects Lab14-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB14_03_EXE
{
    meta:
        description = "Detects Lab14-03.exe from Practical Malware Analysis"
        chapter = "Chapter 14"
        sample = "Lab14-03.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "URLDownloadToCacheFileA"
        $net2 = "Accept-Encoding: gzip, deflate"
        $net3 = "InternetOpenA"
        $net4 = "Accept: */*"
        $dll1 = "WININET.dll" nocase
        $dll2 = "user32.dll" nocase
        $dll3 = "KERNEL32.dll" nocase
        $dll4 = "urlmon.dll" nocase
        $proc1 = "TerminateProcess"
        $proc2 = "CreateProcessA"
        $file1 = "InternetReadFile"
        $file2 = "ReadFile"
        $file3 = "WriteFile"
        $file4 = "CreateFileA"
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "http://www.practicalmalwareanalysis.com/start.htm" nocase
        $susp2 = "WININET.dll" nocase
        $susp3 = "C:\\autobat.exe" nocase
        $susp4 = "user32.dll" nocase
        
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
