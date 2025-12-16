
import "pe"

rule PMA_LAB14_02_EXE
{
    meta:
        description = "Detects Lab14-02.exe from Practical Malware Analysis"
        chapter = "Chapter 14"
        sample = "Lab14-02.exe"
        malware_type = "Process Injector"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "InternetOpenA"
        $net2 = "InternetOpenUrlA"
        $net3 = "DisconnectNamedPipe"
        $dll1 = "WININET.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "USER32.dll" nocase
        $proc1 = "ShellExecuteExA"
        $proc2 = "TerminateProcess"
        $proc3 = "CreateProcessA"
        $file1 = "InternetReadFile"
        $file2 = "ReadFile"
        $file3 = "WriteFile"
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $susp1 = "MSVCRT.dll" nocase
        $susp2 = "cmd.exe" nocase
        $susp3 = "cmd.exe" nocase
        $susp4 = "WININET.dll" nocase
        
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
