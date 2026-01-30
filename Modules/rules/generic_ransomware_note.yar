rule Ransomware_Note_Keywords
{
    meta:
        description = "Detects common ransomware note strings across families"
        author = "Jinay Shah(inspired by ReversingLabs, CISA, AlienLabs)"
        severity = "high"
        reference = "https://github.com/reversinglabs/reversinglabs-yara-rules; https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-302a"
        date = "2026-01-30"
        mitre_technique = "T1486"  // Data Encrypted for Impact
        false_positive_risk = "Low - ransom notes are highly specific"
        detection_stage = "post-impact"
        
    strings:
        // Generic
        $s1 = "Your files are encrypted" ascii wide nocase
        $s2 = "All your files have been encrypted" ascii wide nocase
        $s3 = "decrypt" wide nocase fullword
        $s4 = "bitcoin" wide nocase fullword
        $s5 = "Tor browser" wide nocase
        $s6 = "restore your files" wide nocase
        $s7 = "ransom" ascii wide nocase
        $s8 = "payment" ascii wide nocase
        $s9 = "encrypted by" ascii wide nocase
        $s10 = "decryption key" ascii wide nocase
        $s11 = "pay us" ascii wide nocase
        $s12 = "contact us" ascii wide nocase
        $s13 = ".onion" ascii wide nocase  // Tor sites

        // Family-Specific (LockBit)
        $lockbit1 = "LockBit" ascii wide nocase
        $lockbit2 = "lockbitapt" ascii wide nocase
        $lockbit3 = "Your data are stolen and encrypted" ascii wide nocase
        $lockbit4 = "Restore-My-Files.txt" ascii wide nocase  // Common note file

        // Conti
        $conti1 = "conti" ascii wide nocase
        $conti2 = "CONTI" ascii wide nocase
        $conti3 = "All of your files are currently encrypted by CONTI ransomware" ascii wide nocase
        $conti4 = "CONTI.txt" ascii wide nocase

        // Ryuk
        $ryuk1 = "Ryuk" ascii wide nocase
        $ryuk2 = "RyukReadMe.html" ascii wide nocase
        $ryuk3 = "RyukReadMe.txt" ascii wide nocase
        $ryuk4 = "Your network has been penetrated and all files encrypted" ascii wide nocase

        // BlackCat/ALPHV
        $blackcat1 = "BlackCat" ascii wide nocase
        $blackcat2 = "ALPHV" ascii wide nocase
        $blackcat3 = "RECOVER-FILES.txt" ascii wide nocase
        $blackcat4 = "Your files were encrypted with BlackCat ransomware" ascii wide nocase

        // Other Families (e.g., WannaCry variants)
        $wannacry1 = "WANACRY!" ascii wide nocase
        $wannacry2 = "files has been encrypted with WannaCry" ascii wide nocase
        $wannacry3 = "@WanaDecryptor@" ascii wide nocase

    condition:
        filesize < 10KB and  // Notes are small text files
        (3 of ($s*) or  // Generic
        2 of ($lockbit*) or  // LockBit
        2 of ($conti*) or  // Conti
        2 of ($ryuk*) or  // Ryuk
        2 of ($blackcat*) or  // BlackCat
        2 of ($wannacry*))  // WannaCry
}
