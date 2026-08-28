// SentinelX starter YARA rules — a small, safe-to-ship starting point.
// This is NOT a real threat-hunting ruleset. Replace/extend with a
// curated public set (e.g. Neo23x0/signature-base, YARA Rules Project)
// for genuine detection coverage — these exist so the scanner has
// something to actually match against out of the box.

rule Suspicious_Base64_PowerShell_In_File
{
    meta:
        description = "File contains a long base64 blob near a PowerShell reference"
        severity = "MEDIUM"
    strings:
        $ps = "powershell" nocase
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $ps and $b64
}

rule Embedded_EXE_Header_In_NonExe
{
    meta:
        description = "MZ/PE header found inside a file that isn't a .exe/.dll"
        severity = "HIGH"
    strings:
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
    condition:
        $mz at 0 and $pe
}

rule Known_Ransomware_Note_Strings
{
    meta:
        description = "Common ransom-note phrasing"
        severity = "CRITICAL"
    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "decrypt your files" nocase
        $s3 = "bitcoin" nocase
        $s4 = "restore your files" nocase
    condition:
        2 of ($s1, $s2, $s3, $s4)
}

rule Mimikatz_Strings
{
    meta:
        description = "Strings commonly present in Mimikatz builds"
        severity = "CRITICAL"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "mimikatz" nocase
        $s3 = "gentilkiwi" nocase
    condition:
        any of them
}
