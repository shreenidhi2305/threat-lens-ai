/*
 * ThreatLens AI - static-analysis YARA ruleset.
 *
 * Rules are grouped by ATT&CK tactic. Each carries:
 *   severity : info | low | medium | high   (feeds the risk score)
 *   family   : label used for classification when no signature matches
 *   mitre    : ATT&CK technique id(s)
 *
 * Conditions require multiple corroborating strings so benign files that
 * merely mention an API name do not trip a rule.
 */

/* ===================================================================== *
 *  Reference / test
 * ===================================================================== */

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

/* ===================================================================== *
 *  Execution / delivery
 * ===================================================================== */

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell one-liner that downloads and executes a payload"
        severity    = "high"
        family      = "Downloader"
        mitre       = "T1059.001, T1105"
    strings:
        $ps        = "powershell" nocase
        $iex       = "IEX" nocase
        $iex2      = "Invoke-Expression" nocase
        $downstr   = "DownloadString" nocase
        $downfile  = "DownloadFile" nocase
        $downdata  = "DownloadData" nocase
        $webclient = "Net.WebClient" nocase
        $webreq    = "Invoke-WebRequest" nocase
        $restmeth  = "Invoke-RestMethod" nocase
        $bitstrans = "Start-BitsTransfer" nocase
    condition:
        $ps and 2 of ($iex, $iex2, $downstr, $downfile, $downdata, $webclient, $webreq, $restmeth, $bitstrans)
}

rule PowerShell_Obfuscation_And_Bypass
{
    meta:
        description = "Obfuscated / policy-bypassing PowerShell invocation"
        severity    = "high"
        family      = "Obfuscation"
        mitre       = "T1027, T1059.001, T1562.001"
    strings:
        $enc1  = "-EncodedCommand" nocase
        $enc2  = "-enc " nocase
        $enc3  = "FromBase64String" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $ep    = "-ep bypass" nocase
        $nop   = "-NoProfile" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $w     = "-w hidden" nocase
        $iex   = "IEX" nocase
        $gzip  = "GzipStream" nocase
        $deflate = "DeflateStream" nocase
        $chararr = "-join" nocase
    condition:
        3 of them
}

rule LOLBin_Ingress_Tool_Transfer
{
    meta:
        description = "Living-off-the-land binaries used to fetch remote payloads"
        severity    = "high"
        family      = "Downloader"
        mitre       = "T1105, T1218"
    strings:
        $a = "certutil -urlcache" nocase
        $b = "certutil.exe -urlcache" nocase
        $c = "certutil -decode" nocase
        $d = "bitsadmin /transfer" nocase
        $e = "mshta http" nocase
        $f = "mshta.exe http" nocase
        $g = "regsvr32 /s /n /u /i:http" nocase
        $h = "curl http" nocase
        $i = "wget http" nocase
    condition:
        2 of them
}

rule Malicious_Office_Macro_Dropper
{
    meta:
        description = "VBA auto-exec macro that spawns a shell / drops a file"
        severity    = "high"
        family      = "Dropper"
        mitre       = "T1566.001, T1059.005"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $auto4 = "Auto_Close" nocase
        $sh1   = "CreateObject(\"WScript.Shell\")" nocase
        $sh2   = "Shell(" nocase
        $sh3   = "Wscript.Shell" nocase
        $env   = "Environ(" nocase
        $ado   = "ADODB.Stream" nocase
        $xhr   = "MSXML2.XMLHTTP" nocase
        $ps    = "powershell" nocase
    condition:
        1 of ($auto*) and 2 of ($sh1, $sh2, $sh3, $env, $ado, $xhr, $ps)
}

/* ===================================================================== *
 *  Defense evasion
 * ===================================================================== */

rule Defense_Evasion_Disable_Security_Tools
{
    meta:
        description = "Commands that disable Defender / firewall / logging"
        severity    = "high"
        family      = "DefenseEvasion"
        mitre       = "T1562.001, T1562.004"
    strings:
        $a = "Set-MpPreference -DisableRealtimeMonitoring" nocase
        $b = "Add-MpPreference -ExclusionPath" nocase
        $c = "netsh advfirewall set allprofiles state off" nocase
        $d = "sc stop WinDefend" nocase
        $e = "sc config WinDefend start= disabled" nocase
        $f = "wevtutil cl " nocase
        $g = "Clear-EventLog" nocase
        $h = "DisableAntiSpyware" nocase
    condition:
        2 of them
}

rule AMSI_Bypass_Indicators
{
    meta:
        description = "Strings associated with in-memory AMSI/ETW patching"
        severity    = "high"
        family      = "DefenseEvasion"
        mitre       = "T1562.001"
    strings:
        $a = "AmsiScanBuffer"
        $b = "amsiInitFailed"
        $c = "AmsiUtils"
        $d = "System.Management.Automation.AmsiUtils"
        $e = "EtwEventWrite"
        $f = "[Ref].Assembly.GetType(" nocase
    condition:
        2 of them
}

rule ShadowCopy_Deletion
{
    meta:
        description = "Volume shadow copy deletion (ransomware / anti-recovery)"
        severity    = "high"
        family      = "Impact"
        mitre       = "T1490"
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "vssadmin.exe delete shadows" nocase
        $c = "wmic shadowcopy delete" nocase
        $d = "Win32_ShadowCopy" nocase
        $e = "bcdedit /set {default} recoveryenabled no" nocase
        $f = "wbadmin delete catalog" nocase
    condition:
        2 of them
}

rule Sandbox_Anti_Analysis
{
    meta:
        description = "Sandbox / VM / debugger evasion strings"
        severity    = "medium"
        family      = "AntiAnalysis"
        mitre       = "T1497"
    strings:
        $a = "IsDebuggerPresent"
        $b = "CheckRemoteDebuggerPresent"
        $c = "VBoxService" nocase
        $d = "VBoxTray" nocase
        $e = "vmtoolsd" nocase
        $f = "SbieDll.dll" nocase
        $g = "wine_get_unix_file_name"
        $h = "GetTickCount"
        $i = "Sleep" nocase
    condition:
        3 of them
}

/* ===================================================================== *
 *  Privilege escalation / persistence
 * ===================================================================== */

rule Persistence_Run_Key_Or_Task
{
    meta:
        description = "Registry Run-key / scheduled task / service persistence"
        severity    = "medium"
        family      = "Persistence"
        mitre       = "T1547.001, T1053.005, T1543.003"
    strings:
        $run1 = "\\CurrentVersion\\Run" nocase
        $run2 = "reg add" nocase
        $task = "schtasks /create" nocase
        $task2 = "Register-ScheduledTask" nocase
        $svc  = "New-Service" nocase
        $svc2 = "sc create" nocase
        $wmi  = "__EventFilter" nocase
        $wmi2 = "CommandLineEventConsumer" nocase
        $startup = "\\Start Menu\\Programs\\Startup" nocase
    condition:
        2 of them
}

rule UAC_Bypass_Indicators
{
    meta:
        description = "Known UAC-bypass primitives"
        severity    = "medium"
        family      = "PrivEsc"
        mitre       = "T1548.002"
    strings:
        $a = "fodhelper.exe" nocase
        $b = "computerdefaults.exe" nocase
        $c = "\\ms-settings\\shell\\open\\command" nocase
        $d = "eventvwr.exe" nocase
        $e = "sdclt.exe" nocase
        $f = "DelegateExecute" nocase
    condition:
        2 of them
}

/* ===================================================================== *
 *  Credential access / collection
 * ===================================================================== */

rule Credential_Access_Tooling
{
    meta:
        description = "LSASS dumping / credential theft strings"
        severity    = "high"
        family      = "Stealer"
        mitre       = "T1003, T1555.003"
    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "mimikatz" nocase
        $c = "lsass.exe" nocase
        $d = "MiniDumpWriteDump"
        $e = "comsvcs.dll, MiniDump" nocase
        $f = "\\Login Data"
        $g = "\\Local State"
        $h = "moz_logins"
        $i = "wallet.dat"
        $j = "Local\\Google\\Chrome\\User Data" nocase
    condition:
        2 of them
}

rule Keylogger_Indicators
{
    meta:
        description = "Keystroke capture API usage"
        severity    = "medium"
        family      = "Spyware"
        mitre       = "T1056.001"
    strings:
        $a = "SetWindowsHookEx"
        $b = "GetAsyncKeyState"
        $c = "GetKeyboardState"
        $d = "WH_KEYBOARD_LL"
        $e = "GetForegroundWindow"
    condition:
        3 of them
}

/* ===================================================================== *
 *  Injection / C2
 * ===================================================================== */

rule Process_Injection_APIs
{
    meta:
        description = "Classic remote-process injection API set"
        severity    = "medium"
        family      = "Injector"
        mitre       = "T1055"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtCreateThreadEx"
        $e = "QueueUserAPC"
        $f = "NtUnmapViewOfSection"
        $g = "SetThreadContext"
        $h = "RtlCreateUserThread"
    condition:
        3 of them
}

rule CobaltStrike_Beacon_Indicators
{
    meta:
        description = "Artifacts consistent with a Cobalt Strike beacon"
        severity    = "high"
        family      = "Beacon"
        mitre       = "T1071.001, T1573"
    strings:
        $a = "beacon.dll" nocase
        $b = "%s as %s\\%s: %d"
        $c = "ReflectiveLoader"
        $d = "/submit.php?id="
        $e = "MSSE-" nocase
        $f = "Content-Type: application/octet-stream"
        $g = "spawnto_x86"
        $h = "malleable"
    condition:
        2 of them
}

rule C2_Beacon_Config
{
    meta:
        description = "Hard-coded C2 URL plus beacon-style HTTP config"
        severity    = "high"
        family      = "Backdoor"
        mitre       = "T1071.001, T1571"
    strings:
        $c2a  = "X-Malware-C2:" nocase
        $c2b  = "C2:" nocase
        $gate = "/gate.php" nocase
        $panel = "/panel/" nocase
        $ua   = "User-Agent: Mozilla" nocase
        $beacon = "beacon" nocase
        $sleep  = /sleep\s*[:=]\s*\d{3,}/ nocase
        $url    = /https?:\/\/(\d{1,3}\.){3}\d{1,3}[\/:]/
    condition:
        $url and 2 of ($c2a, $c2b, $gate, $panel, $ua, $beacon, $sleep)
}

/* ===================================================================== *
 *  Impact
 * ===================================================================== */

rule Ransomware_Note_Or_Behavior
{
    meta:
        description = "Ransom-note language or bulk-encryption behavior"
        severity    = "high"
        family      = "Ransomware"
        mitre       = "T1486, T1490"
    strings:
        $n1 = "your files have been encrypted" nocase
        $n2 = "all your files" nocase
        $n3 = "decryption key" nocase
        $n4 = "bitcoin" nocase
        $n5 = "BTC wallet" nocase
        $n6 = ".onion" nocase
        $n7 = "pay the ransom" nocase
        $b1 = "CryptEncrypt"
        $b2 = "BCryptEncrypt"
        $b3 = ".locked"
        $b4 = "README_TO_DECRYPT" nocase
        $b5 = "vssadmin delete shadows" nocase
    condition:
        3 of them
}

rule WebShell_Indicators
{
    meta:
        description = "Server-side web shell (PHP / ASPX / JSP)"
        severity    = "high"
        family      = "WebShell"
        mitre       = "T1505.003"
    strings:
        $php1 = "<?php" nocase
        $php2 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|\$_(POST|GET|REQUEST))/ nocase
        $php3 = "shell_exec($_" nocase
        $php4 = "system($_" nocase
        $php5 = "assert($_" nocase
        $asp1 = "eval(Request" nocase
        $asp2 = "Server.CreateObject(\"WScript.Shell\")" nocase
        $jsp1 = "Runtime.getRuntime().exec(request." nocase
    condition:
        ($php1 and 1 of ($php2, $php3, $php4, $php5)) or 1 of ($asp1, $asp2, $jsp1)
}

/* ===================================================================== *
 *  Obfuscation / packing
 * ===================================================================== */

rule Embedded_Base64_Blob
{
    meta:
        description = "Large base64 blob embedded in the file (possible packed payload)"
        severity    = "low"
        family      = "Obfuscation"
        mitre       = "T1027"
    strings:
        $b64      = /[A-Za-z0-9+\/]{512,}={0,2}/
        $mz_b64   = "TVqQAAMAAAAEAAAA"   /* base64 of "MZ\x90\0\x03\0\0\0\x04\0\0\0" */
    condition:
        $mz_b64 or #b64 >= 1
}

rule Known_Packer_Section_Names
{
    meta:
        description = "PE section names left by common runtime packers"
        severity    = "medium"
        family      = "Packed"
        mitre       = "T1027.002"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $aspack = ".aspack"
        $mpress = ".MPRESS1"
        $themida = ".themida"
        $pecompact = "PEC2"
        $petite = ".petite"
        $fsg = "FSG!"
    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule Embedded_PE_In_NonExecutable
{
    meta:
        description = "A second PE header embedded well inside a non-PE file"
        severity    = "medium"
        family      = "Dropper"
        mitre       = "T1027.009"
    strings:
        $mz = { 4D 5A }
        $pe = "This program cannot be run in DOS mode"
    condition:
        uint16(0) != 0x5A4D and $pe and #mz >= 1
}
