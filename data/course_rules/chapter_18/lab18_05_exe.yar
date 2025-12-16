/*
    YARA-X Rule for Lab18_05.exe
    Chapter: Chapter 18
    Sample: Lab18_05.exe (注意下划线)
    Malware Type: Shellcode Executor
    
    Description: Detects Lab18_05.exe - packed sample
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_Lab18_05_EXE
{
    meta:
        description = "Detects Lab18_05.exe (packed sample)"
        chapter = "Chapter 18"
        sample = "Lab18_05.exe"
        malware_type = "Shellcode Executor"
        severity = "high"
        
    strings:
        $fake_dll = "MZKERNEL32.DLL"
        $load_lib = "LoadLibraryA"
        $get_proc = "GetProcAddress"
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        2 of them
}