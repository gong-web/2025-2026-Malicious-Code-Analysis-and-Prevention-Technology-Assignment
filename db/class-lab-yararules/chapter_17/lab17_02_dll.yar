/*
    YARA-X Rule for Lab17-02.dll
    Chapter: Chapter 17
    Sample: Lab17-02.dll
    Malware Type: Service/Backdoor
    
    Description: Detects Lab17-02.dll from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB17_02_DLL
{
    meta:
        description = "Detects Lab17-02.dll from Practical Malware Analysis"
        chapter = "Chapter 17"
        sample = "Lab17-02.dll"
        malware_type = "Service/Backdoor"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*"
        $net2 = "Connection: Keep-Alive"
        $net3 = "Microsoft TV/Video Connection"
        $net4 = "WmsgSendMessage"
        $dll1 = "Kernel32"
        $dll2 = "user32.dll" nocase
        $dll3 = "kernel32"
        $dll4 = "ADVAPI32.dll" nocase
        $proc1 = "TerminateProcess"
        $proc2 = "CreateProcess() GetLastError reports %d"
        $proc3 = "CreateProcessAsUserA"
        $proc4 = "WriteProcessMemory"
        $file1 = "MoveFileA"
        $file2 = "ReadFile"
        $file3 = "CreateFileA"
        $file4 = "WriteFile"
        $reg_api1 = "RegSetValueEx(ServiceMain)"
        $reg_api2 = "RegQueryValueExA"
        $reg_api3 = "RegOpenKeyEx(%s) KEY_QUERY_VALUE error %d."
        $reg_api4 = "RegDeleteKeyA"
        $reg_key1 = "SYSTEM\\CurrentControlSet\\Services\\" nocase
        $reg_key2 = "SYSTEM\\CurrentControlSet\\Services\\" nocase
        $reg_key3 = "HKEY_CURRENT_USER"
        $reg_key4 = "QueryServiceStatus"
        $svc1 = "OpenSCManager() error %d"
        $svc2 = "StartServiceA"
        $svc3 = "ControlService"
        $svc4 = "StartService '%s' Successfully"
        $import1 = "GetModuleHandleA"
        $import2 = "Sleep"
        $import3 = "LoadLibraryW"
        $import4 = "GetProcAddress"
        $susp1 = "\\command.exe /c " nocase
        $susp2 = "iphlpapi.dll" nocase
        $susp3 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" nocase
        $susp4 = ".dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) != 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            2 of ($proc*)
        ) and (
            1 of ($file*) or (1 of ($reg_api*) or 1 of ($reg_key*)) or 1 of ($svc*) or 1 of ($import*) or 1 of ($susp*)
        )
}
