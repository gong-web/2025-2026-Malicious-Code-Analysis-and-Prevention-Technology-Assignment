/*
    YARA-X Rule for PMA_Persistence_Registry_Generic
    Chapter: Generic
    Sample: PMA_Persistence_Registry_Generic
    Malware Type: Malware
    
    Description: Generic registry persistence pattern for PMA samples
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_Persistence_Registry_Generic
{
    meta:
        description = "Generic registry persistence pattern for PMA samples"
        severity = "medium"
        
    strings:
        $reg_run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg_open = "RegOpenKeyExA" nocase
        $reg_set = "RegSetValueExA" nocase
        $reg_create = "RegCreateKeyExA" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        $reg_run and
        2 of ($reg_open, $reg_set, $reg_create)
}