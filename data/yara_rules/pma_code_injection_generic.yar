/*
    YARA-X Rule for PMA_Code_Injection_Generic
    Chapter: Generic
    Sample: PMA_Code_Injection_Generic
    Malware Type: Malware
    
    Description: Generic code injection pattern for PMA samples
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_Code_Injection_Generic
{
    meta:
        description = "Generic code injection pattern for PMA samples"
        severity = "high"
        
    strings:
        $inject1 = "VirtualAllocEx" nocase
        $inject2 = "WriteProcessMemory" nocase
        $inject3 = "CreateRemoteThread" nocase
        $inject4 = "OpenProcess" nocase
        $inject5 = "NtUnmapViewOfSection" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        3 of them
}