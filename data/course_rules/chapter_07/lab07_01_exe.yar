import "pe"

rule PMA_Lab07_01_EXE
{
    meta:
        description = "Detects Lab07_01.exe from Practical Malware Analysis"
        chapter = "Chapter 7"
        sample = "Lab07_01.exe"
        malware_type = "Mutex-based Malware"
        severity = "medium"
        
    strings:
        $create_mutex = "CreateMutexA" nocase
        $wait_single = "WaitForSingleObject" nocase
        $mutex_name = "SADFHUHF" nocase
        $kernel32 = "kernel32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        not (pe.characteristics & 0x2000) and
        3 of them
}