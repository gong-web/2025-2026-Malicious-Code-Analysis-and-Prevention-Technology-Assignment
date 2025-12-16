import "pe"
import "math"

rule IsPacked {
    meta:
        description = "Generic Packer Detection via High Entropy and Section Names"
    condition:
        math.entropy(0, filesize) >= 7.5 or
        for any section in pe.sections : (
            section.name == "UPX0" or
            section.name == "UPX1" or
            section.name == ".MPRESS1" or
            section.name == ".MPRESS2" or
            math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.8
        )
}

rule anti_dbg {
    meta:
        description = "Generic Anti-Debugging Detection"
    strings:
        $s1 = "IsDebuggerPresent" nocase
        $s2 = "CheckRemoteDebuggerPresent" nocase
        $s3 = "OutputDebugString" nocase
        $s4 = "FindWindow" nocase
        $s5 = "NtGlobalFlag" nocase
    condition:
        any of them
}

rule powershell {
    meta:
        description = "Powershell usage"
    strings:
        $s1 = "powershell" nocase wide ascii
        $s2 = "Invoke-Expression" nocase wide ascii
    condition:
        any of them
}
