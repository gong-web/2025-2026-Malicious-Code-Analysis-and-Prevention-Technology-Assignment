/*
    YARA-X Rule for PMA_Network_Backdoor_Generic
    Chapter: Generic
    Sample: PMA_Network_Backdoor_Generic
    Malware Type: Malware
    
    Description: Generic network backdoor pattern for PMA samples
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_Network_Backdoor_Generic
{
    meta:
        description = "Generic network backdoor pattern for PMA samples"
        severity = "high"
        
    strings:
        $net1 = "ws2_32.dll" nocase
        $net2 = "wininet.dll" nocase
        $func1 = "socket" nocase
        $func2 = "recv" nocase
        $func3 = "send" nocase
        $func4 = "connect" nocase
        $shell = "cmd.exe" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        ($net1 or $net2) and
        3 of ($func*) and
        $shell
}