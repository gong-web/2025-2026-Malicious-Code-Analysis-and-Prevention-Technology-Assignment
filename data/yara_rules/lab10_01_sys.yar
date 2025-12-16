import "pe"

rule PMA_LAB10_01_SYS
{
    meta:
        description = "Detects Lab10-01.sys rootkit driver"
        sample = "Lab10-01.sys"
        chapter = "Chapter 10"
        malware_type = "Kernel Rootkit"
        
    condition:
        uint16(0) == 0x5A4D and
        filesize == 3712 and
        pe.characteristics == 0x0102 and
        pe.number_of_sections == 6
}