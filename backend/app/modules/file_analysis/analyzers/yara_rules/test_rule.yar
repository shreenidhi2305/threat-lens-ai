rule Suspicious_PowerShell
{
    meta:
        description = "Detects a PowerShell command pattern"
        author = "ThreatLens AI"
        severity = "medium"

    strings:
        $powershell = "powershell"
        $command = "-Command"

    condition:
        $powershell and $command
}
