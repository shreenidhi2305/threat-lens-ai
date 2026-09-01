/*
 * ThreatLens AI - baseline static-analysis YARA rules.
 * Intentionally small and readable. Extend per malware family as the
 * signature/research workflow matures.
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (harmless standard test string)"
        severity    = "info"
        family      = "Test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell one-liner commonly used to download and run a payload"
        severity    = "high"
        family      = "Downloader"
    strings:
        $ps        = "powershell" nocase
        $iex       = "IEX" nocase
        $downstr   = "DownloadString" nocase
        $downfile  = "DownloadFile" nocase
        $webclient = "Net.WebClient" nocase
        $hidden    = "-WindowStyle Hidden" nocase
        $enc       = "-EncodedCommand" nocase
    condition:
        $ps and (2 of ($iex, $downstr, $downfile, $webclient, $hidden, $enc))
}

rule Windows_Process_Injection_APIs
{
    meta:
        description = "Imports/strings associated with classic process injection"
        severity    = "medium"
        family      = "Injector"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtUnmapViewOfSection"
        $e = "SetThreadContext"
    condition:
        2 of them
}

rule Embedded_Base64_Blob
{
    meta:
        description = "Large base64 blob embedded in the file (possible packed payload)"
        severity    = "low"
        family      = "Obfuscation"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        $b64
}

rule Suspicious_Windows_Shell_Commands
{
    meta:
        description = "Living-off-the-land shell commands often seen in droppers"
        severity    = "medium"
        family      = "Dropper"
    strings:
        $a = "cmd.exe /c" nocase
        $b = "vssadmin delete shadows" nocase
        $c = "bcdedit /set" nocase
        $d = "schtasks /create" nocase
        $e = "reg add" nocase
        $f = "certutil -urlcache" nocase
    condition:
        2 of them
}
