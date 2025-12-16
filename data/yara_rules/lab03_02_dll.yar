/*
    YARA-X Rule for Lab03-02.dll
    Chapter: Chapter 3
    Sample: Lab03-02.dll
    Malware Type: Service/Backdoor
    
    Description: Detects Lab03-02.dll from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB03_02_DLL
{
    meta:
        description = "Detects Lab03-02.dll from Practical Malware Analysis"
        chapter = "Chapter 3"
        sample = "Lab03-02.dll"
        malware_type = "Service/Backdoor"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "HttpOpenRequestA"
        $net2 = "InternetOpenA"
        $net3 = "WSASocketA"
        $net4 = "InternetConnectA"
        $dll1 = "WININET.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "ADVAPI32.dll" nocase
        $dll4 = "WS2_32.dll" nocase
        $proc1 = "CreateProcessA"
        $file1 = "InternetReadFile"
        $file2 = "ReadFile"
        $file3 = "GetTempPathA"
        $reg_api1 = "RegCreateKeyA"
        $reg_api2 = "RegSetValueExA"
        $reg_api3 = "RegOpenKeyEx(%s) KEY_QUERY_VALUE success."
        $reg_api4 = "RegOpenKeyExA"
        $reg_key1 = "SYSTEM\\CurrentControlSet\\Services\\" nocase
        $reg_key2 = "SYSTEM\\CurrentControlSet\\Services\\" nocase
        $reg_key3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" nocase
        $reg_key4 = "SetServiceStatus"
        $svc1 = "DeleteService"
        $svc2 = "CreateServiceA"
        $svc3 = "CreateService(%s) error %d"
        $svc4 = "OpenSCManagerA"
        $import1 = "Sleep"
        $import2 = "GetProcAddress"
        $import3 = "LoadLibraryA"
        $susp1 = "MSVCRT.dll" nocase
        $susp2 = "WININET.dll" nocase
        $susp3 = "%SystemRoot%\\System32\\svchost.exe -k " nocase
        $susp4 = ".exe" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) != 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            1 of ($proc*)
        ) and (
            1 of ($file*) or (1 of ($reg_api*) or 1 of ($reg_key*)) or 1 of ($svc*) or 1 of ($import*) or 1 of ($susp*)
        )
}