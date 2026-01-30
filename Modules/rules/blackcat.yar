rule Win32_Ransomware_BlackCat
{
    meta:
        description = "Detects BlackCat (ALPHV/Noberus) ransomware"
        author = "Jinay Shah (from AlienLabs, ReversingLabs, CloudSEK)"
        severity = "critical"
        reference = "https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/yara/ransomware/Win32.Ransomware.BlackCat.yara; https://cybersecurity.att.com/blogs/labs-research/blackcat-ransomware"
        date = "2026-01-30"
        mitre_technique = "T1486"
        false_positive_risk = "Low"
        hash_example = "6660d0e87a142ab1bde4521d9c6f5e148490b05a57c71122e28280b35452e896"

    strings:
        // Code patterns (Rust-based)
        $rust = "/rust/" ascii wide  // Rust artifact
        $code1 = { 8d4701 31c9 31d2 89460c 4f c745f000000000 }  // Encryption loop

        // Strings
        $str1 = "BlackCat" ascii wide nocase
        $str2 = "ALPHV" ascii wide nocase
        $str3 = "RECOVER-FILES.txt" ascii nocase
        $str4 = "Your files were encrypted with BlackCat ransomware" ascii wide nocase
        $str5 = ".alphv" ascii nocase  // Extension
        $str6 = "enable_esxi_vm_kill" ascii nocase  // ESXi targeting

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $rust and  // Rust indicator
        (1 of ($code*) or  // Code
        2 of ($str*))  // Strings
}
