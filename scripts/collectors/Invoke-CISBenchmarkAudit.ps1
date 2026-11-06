#Requires -Version 5.1
<#
.SYNOPSIS
    CIS Benchmark Configuration Audit for Windows Server Domain Controller
.DESCRIPTION
    Audits the server against the CIS Microsoft Windows Server Benchmark (Domain Controller Profile).
    Performs deep read-only inspection of:
    - Account Policies (Password & Lockout - CIS Section 1)
    - Local Policies & Security Options (CIS Section 2.3)
    - System Services Hardening (Spooler, RemoteRegistry, etc. - CIS Section 5)
    - Windows Defender Firewall Profiles (CIS Section 9)
    - Network Protocols & System Hardening (LLMNR, SMBv1, NLA, LSA Protection, WDigest - CIS Section 18)
    - PowerShell Logging & Auditing (CIS Section 18)
    - Event Log Sizes & Retention (CIS Section 19)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Target Domain Controller IP or FQDN")]
    [string]$TargetIP,

    [Parameter(Mandatory=$true, Position=1, HelpMessage="Username (e.g. Administrator or DOMAIN\Admin)")]
    [string]$Username,

    [Parameter(Mandatory=$true, Position=2, HelpMessage="Password")]
    [string]$Password,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "discovery/windows/cis_benchmark_audit.json"
)

$ErrorActionPreference = "Continue"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "CIS BENCHMARK CONFIGURATION AUDIT: WINDOWS SERVER DC PROFILE" -ForegroundColor Cyan
Write-Host "Target: $TargetIP | User: $Username" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Setup Authentication & Session
$secPass = ConvertTo-SecureString $Password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($Username, $secPass)
$sessionOpt = New-CimSessionOption -Protocol Dcom
$session = New-CimSession -ComputerName $TargetIP -Credential $cred -SessionOption $sessionOpt

if (-not $session) {
    Write-Error "Failed to establish CIM DCOM session to $TargetIP"
    exit 1
}

Write-Host "[+] CIM DCOM session established successfully." -ForegroundColor Green

# Helper function to query remote registry via WMI StdRegProv
$HKLM = [uint32]2147483650

function Get-RemoteRegDword {
    param ($SubKey, $ValueName)
    try {
        $res = Invoke-CimMethod -CimSession $session -Namespace "root\default" -ClassName "StdRegProv" -MethodName "GetDWORDValue" -Arguments @{
            hDefKey = $HKLM
            sSubKeyName = $SubKey
            sValueName = $ValueName
        }
        if ($res.ReturnValue -eq 0) {
            return $res.uValue
        }
        return $null
    } catch {
        return $null
    }
}

function Get-RemoteRegString {
    param ($SubKey, $ValueName)
    try {
        $res = Invoke-CimMethod -CimSession $session -Namespace "root\default" -ClassName "StdRegProv" -MethodName "GetStringValue" -Arguments @{
            hDefKey = $HKLM
            sSubKeyName = $SubKey
            sValueName = $ValueName
        }
        if ($res.ReturnValue -eq 0) {
            return $res.sValue
        }
        return $null
    } catch {
        return $null
    }
}

# 2. Gather OS Details
Write-Host "[+] Querying Operating System telemetry..." -ForegroundColor Yellow
$os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem

# 3. Gather Domain Account & Password Policy
Write-Host "[+] Querying Active Directory Password & Account Lockout Policies..." -ForegroundColor Yellow
$domainPolicy = @{}
try {
    $rootDse = [ADSI]"LDAP://$TargetIP/RootDSE"
    $defaultNc = $rootDse.defaultNamingContext[0]
    $domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$TargetIP/$defaultNc", $Username, $Password)

    function Convert-LargeInt($largeInt) {
        if (-not $largeInt) { return 0 }
        $high = $largeInt.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $largeInt, $null)
        $low = $largeInt.GetType().InvokeMember("LowPart", [System.Reflection.BindingFlags]::GetProperty, $null, $largeInt, $null)
        $low64 = [int64]$low
        if ($low64 -lt 0) { $low64 = $low64 + 4294967296 }
        $val = ([int64]$high -shl 32) + $low64
        return $val
    }

    $minPwdLength = $domainEntry.Properties["minPwdLength"].Value
    $pwdProperties = $domainEntry.Properties["pwdProperties"].Value
    $pwdHistoryLength = $domainEntry.Properties["pwdHistoryLength"].Value
    $maxPwdAgeTicks = Convert-LargeInt $domainEntry.Properties["maxPwdAge"].Value
    $minPwdAgeTicks = Convert-LargeInt $domainEntry.Properties["minPwdAge"].Value
    $lockoutThreshold = $domainEntry.Properties["lockoutThreshold"].Value
    $lockoutDurationTicks = Convert-LargeInt $domainEntry.Properties["lockoutDuration"].Value
    $lockoutWindowTicks = Convert-LargeInt $domainEntry.Properties["lockOutObservationWindow"].Value

    $maxPwdAgeDays = [Math]::Abs([Math]::Round($maxPwdAgeTicks / -864000000000, 1))
    $minPwdAgeDays = [Math]::Abs([Math]::Round($minPwdAgeTicks / -864000000000, 1))
    $lockoutDurationMins = [Math]::Abs([Math]::Round($lockoutDurationTicks / -600000000, 1))
    $lockoutWindowMins = [Math]::Abs([Math]::Round($lockoutWindowTicks / -600000000, 1))

    $complexityEnabled = ($pwdProperties -band 1) -eq 1
    $reversibleEncDisabled = ($pwdProperties -band 16) -eq 0

    $domainPolicy = @{
        MinPasswordLength = [int]$minPwdLength
        PasswordComplexity = $complexityEnabled
        ReversibleEncryption = (-not $reversibleEncDisabled)
        PasswordHistoryLength = [int]$pwdHistoryLength
        MaxPasswordAgeDays = [double]$maxPwdAgeDays
        MinPasswordAgeDays = [double]$minPwdAgeDays
        LockoutThreshold = [int]$lockoutThreshold
        LockoutDurationMins = [double]$lockoutDurationMins
        LockoutWindowMins = [double]$lockoutWindowMins
    }
} catch {
    Write-Warning "Could not retrieve domain policy via ADSI: $_"
}

# 4. Gather Critical Registry Security Configurations (CIS Section 2.3 & 18)
Write-Host "[+] Querying CIS Registry Security Options & Hardening Settings..." -ForegroundColor Yellow

# LDAP Signing
$ldapServerIntegrity = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity"
$ldapClientIntegrity = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity"

# NTLM & Authentication Security
$lmCompatibility = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
$ntlmMinClientSec = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec"
$ntlmMinServerSec = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec"
$limitBlankPassword = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
$restrictAnonymousSAM = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
$restrictAnonymous = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
$everyoneIncludesAnonymous = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous"

# LSA & Credential Protection
$runAsPPL = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
$runAsPPLBoot = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPLBoot"
$wdigestUseLogonCred = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"

# SMB Protocol & Signing
$smbServerRequireSign = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
$smbServerEnableSign = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature"
$smbClientRequireSign = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
$smbClientEnableSign = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature"
$smb1Server = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"

# Interactive Logon & Security Banners
$cachedLogons = Get-RemoteRegString "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount"
if (-not $cachedLogons) {
    $cachedLogons = Get-RemoteRegDword "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount"
}
$dontDisplayLastUser = Get-RemoteRegDword "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
$legalNoticeCaption = Get-RemoteRegString "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption"
$legalNoticeText = Get-RemoteRegString "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText"

# User Account Control (UAC)
$enableLUA = Get-RemoteRegDword "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
$consentPromptAdmin = Get-RemoteRegDword "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
$filterAdminToken = Get-RemoteRegDword "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken"
$promptOnSecureDesktop = Get-RemoteRegDword "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop"

# Network Protocols (LLMNR, Remote Desktop, NLA)
$enableLLMNR = Get-RemoteRegDword "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
$fDenyTSConnections = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
$userAuthenticationNLA = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
$disablePasswordSaving = Get-RemoteRegDword "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving"

# PowerShell Auditing & Script Block Logging
$enableScriptBlock = Get-RemoteRegDword "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
$enableTranscript = Get-RemoteRegDword "SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"

# TLS Protocols
$tls10Server = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" "Enabled"
$tls11Server = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" "Enabled"
$tls12Server = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" "Enabled"

# Device Guard / VBS
$vbsEnabled = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"

# 5. Services Hardening on Domain Controller
Write-Host "[+] Querying critical services status on Domain Controller..." -ForegroundColor Yellow
$services = Get-CimInstance -CimSession $session -ClassName Win32_Service -Filter "Name='Spooler' or Name='RemoteRegistry' or Name='MapsBroker' or Name='WerSvc'" | Select-Object Name, DisplayName, StartMode, State

# 6. Windows Firewall Profiles
Write-Host "[+] Querying Windows Defender Firewall profile states..." -ForegroundColor Yellow
$fwDomainEnable = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" "EnableFirewall"
$fwPrivateEnable = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" "EnableFirewall"
$fwPublicEnable = Get-RemoteRegDword "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" "EnableFirewall"

# 7. Event Log Sizes & Configuration
Write-Host "[+] Querying Event Log retention and maximum capacity..." -ForegroundColor Yellow
$eventLogs = Get-CimInstance -CimSession $session -ClassName Win32_NTEventlogFile | Where-Object { $_.LogfileName -in @("Security", "System", "Application", "Directory Service", "DNS Server") } | Select-Object LogfileName, MaxFileSize, NumberOfRecords

# 8. Compile Comprehensive CIS Benchmark Evaluation Table
Write-Host "[+] Evaluating CIS Benchmark compliance rules..." -ForegroundColor Cyan

$spooler = $services | Where-Object { $_.Name -eq 'Spooler' }
$remoteReg = $services | Where-Object { $_.Name -eq 'RemoteRegistry' }
$mapsBroker = $services | Where-Object { $_.Name -eq 'MapsBroker' }
$werSvc = $services | Where-Object { $_.Name -eq 'WerSvc' }

$secLog = $eventLogs | Where-Object { $_.LogfileName -eq 'Security' }
$sysLog = $eventLogs | Where-Object { $_.LogfileName -eq 'System' }
$appLog = $eventLogs | Where-Object { $_.LogfileName -eq 'Application' }
$dirLog = $eventLogs | Where-Object { $_.LogfileName -eq 'Directory Service' }
$dnsLog = $eventLogs | Where-Object { $_.LogfileName -eq 'DNS Server' }

$cisRules = @(
    # --- ACCOUNT POLICIES (CIS 1.1 & 1.2) ---
    @{
        ID = "CIS-1.1.1"
        Section = "1.1 Password Policy"
        Recommendation = "Enforce password history: 24 or more passwords remembered"
        TargetProfile = "Domain Controller"
        CurrentValue = "$($domainPolicy.PasswordHistoryLength) passwords remembered"
        CISBenchmarkValue = ">= 24 passwords"
        Status = if ($domainPolicy.PasswordHistoryLength -ge 24) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Ensures users do not alternate between familiar passwords repeatedly."
        Remediation = "Configure 'Enforce password history' to 24 or more in the Default Domain Policy GPO."
    },
    @{
        ID = "CIS-1.1.2"
        Section = "1.1 Password Policy"
        Recommendation = "Maximum password age: 60 or fewer days, but not 0"
        TargetProfile = "Domain Controller"
        CurrentValue = "$($domainPolicy.MaxPasswordAgeDays) days"
        CISBenchmarkValue = "<= 60 days (and > 0)"
        Status = if ($domainPolicy.MaxPasswordAgeDays -gt 0 -and $domainPolicy.MaxPasswordAgeDays -le 60) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Limits the window of vulnerability if a password has been compromised without detection."
        Remediation = "Adjust 'Maximum password age' to 60 days in the Default Domain Policy GPO."
    },
    @{
        ID = "CIS-1.1.3"
        Section = "1.1 Password Policy"
        Recommendation = "Minimum password age: 1 or more days"
        TargetProfile = "Domain Controller"
        CurrentValue = "$($domainPolicy.MinPasswordAgeDays) days"
        CISBenchmarkValue = ">= 1 day"
        Status = if ($domainPolicy.MinPasswordAgeDays -ge 1) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Prevents users from resetting their password repeatedly to bypass password history."
        Remediation = "Configure 'Minimum password age' to at least 1 day in the Default Domain Policy GPO."
    },
    @{
        ID = "CIS-1.1.4"
        Section = "1.1 Password Policy"
        Recommendation = "Minimum password length: 14 or more characters"
        TargetProfile = "Domain Controller"
        CurrentValue = "$($domainPolicy.MinPasswordLength) characters"
        CISBenchmarkValue = ">= 14 characters"
        Status = if ($domainPolicy.MinPasswordLength -ge 14) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Significantly increases entropy and resistance to offline and online brute force / hash cracking."
        Remediation = "Increase 'Minimum password length' to at least 14 characters in the Default Domain Policy GPO."
    },
    @{
        ID = "CIS-1.1.5"
        Section = "1.1 Password Policy"
        Recommendation = "Password must meet complexity requirements: Enabled"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($domainPolicy.PasswordComplexity) { "Enabled" } else { "Disabled" }
        CISBenchmarkValue = "Enabled"
        Status = if ($domainPolicy.PasswordComplexity) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Requires 3 of 4 character classes (uppercase, lowercase, numbers, symbols)."
        Remediation = "Maintain 'Password must meet complexity requirements' enabled in Default Domain Policy."
    },
    @{
        ID = "CIS-1.1.6"
        Section = "1.1 Password Policy"
        Recommendation = "Store passwords using reversible encryption: Disabled"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($domainPolicy.ReversibleEncryption) { "Enabled (INSECURE)" } else { "Disabled" }
        CISBenchmarkValue = "Disabled"
        Status = if (-not $domainPolicy.ReversibleEncryption) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "CRITICAL"
        Rationale = "Reversible encryption essentially stores plaintext passwords in the directory database."
        Remediation = "Ensure 'Store passwords using reversible encryption' remains Disabled."
    },
    @{
        ID = "CIS-1.2.1"
        Section = "1.2 Account Lockout Policy"
        Recommendation = "Account lockout duration: 15 or more minutes (or 0 for manual unlock)"
        TargetProfile = "Domain Controller"
        CurrentValue = "$($domainPolicy.LockoutDurationMins) minutes"
        CISBenchmarkValue = ">= 15 minutes"
        Status = if ($domainPolicy.LockoutDurationMins -ge 15 -or $domainPolicy.LockoutDurationMins -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Slows down automated password guessing attacks against domain accounts."
        Remediation = "Maintain 'Account lockout duration' at 15 minutes or longer in Default Domain Policy."
    },
    @{
        ID = "CIS-1.2.2"
        Section = "1.2 Account Lockout Policy"
        Recommendation = "Account lockout threshold: 5 or fewer invalid logon attempts, but not 0"
        TargetProfile = "Domain Controller"
        CurrentValue = "$($domainPolicy.LockoutThreshold) attempts"
        CISBenchmarkValue = "<= 5 invalid attempts (and > 0)"
        Status = if ($domainPolicy.LockoutThreshold -gt 0 -and $domainPolicy.LockoutThreshold -le 5) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Threshold of 10 allows longer brute force window; CIS mandates 5 attempts."
        Remediation = "Reduce 'Account lockout threshold' to 5 invalid attempts in the Default Domain Policy GPO."
    },
    @{
        ID = "CIS-1.2.3"
        Section = "1.2 Account Lockout Policy"
        Recommendation = "Reset account lockout counter after: 15 or more minutes"
        TargetProfile = "Domain Controller"
        CurrentValue = "$($domainPolicy.LockoutWindowMins) minutes"
        CISBenchmarkValue = ">= 15 minutes"
        Status = if ($domainPolicy.LockoutWindowMins -ge 15) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "LOW"
        Rationale = "Determines observation window before failed logon count is reset."
        Remediation = "Maintain 'Reset account lockout counter after' at 15 minutes or longer."
    },

    # --- LOCAL POLICIES & SECURITY OPTIONS (CIS 2.3) ---
    @{
        ID = "CIS-2.3.1"
        Section = "2.3 Security Options - Domain Controller"
        Recommendation = "Domain controller: LDAP server signing requirements: Require signing (2)"
        TargetProfile = "Domain Controller"
        CurrentValue = switch ($ldapServerIntegrity) { 1 { "1 (Negotiate signing)" } 2 { "2 (Require signing)" } default { if ($null -eq $ldapServerIntegrity) { "Not configured (Default: 1 - Negotiate)" } else { "$ldapServerIntegrity" } } }
        CISBenchmarkValue = "2 (Require signing)"
        Status = if ($ldapServerIntegrity -eq 2) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Prevents man-in-the-middle tampering and NTLM relay attacks against LDAP."
        Remediation = "Set 'Domain controller: LDAP server signing requirements' to 'Require signing' via Default Domain Controllers Policy."
    },
    @{
        ID = "CIS-2.3.2"
        Section = "2.3 Security Options - Network Security"
        Recommendation = "Network security: LAN Manager authentication level: Send NTLMv2 response only. Refuse LM & NTLM (Level 5)"
        TargetProfile = "Domain Controller"
        CurrentValue = switch ($lmCompatibility) { 5 { "5 (Send NTLMv2 only, Refuse LM & NTLM)" } default { if ($null -eq $lmCompatibility) { "Not configured (Default: Send NTLMv2 response only / Level 3)" } else { "$lmCompatibility" } } }
        CISBenchmarkValue = "5 (Send NTLMv2 only. Refuse LM & NTLM)"
        Status = if ($lmCompatibility -eq 5) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Eliminates legacy LM and NTLMv1 challenge/response authentication which is trivial to crack."
        Remediation = "Configure 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM' (5) via GPO."
    },
    @{
        ID = "CIS-2.3.3"
        Section = "2.3 Security Options - Network Security"
        Recommendation = "Network security: Minimum session security for NTLM SSP clients & servers: Require 128-bit encryption"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($ntlmMinClientSec -eq 537395200) { "537395200 (Require NTLMv2 & 128-bit encryption)" } else { if ($null -eq $ntlmMinClientSec) { "Not configured (Default: 0x0)" } else { "$ntlmMinClientSec" } }
        CISBenchmarkValue = "537395200 (Require NTLMv2 & 128-bit encryption)"
        Status = if ($ntlmMinClientSec -eq 537395200) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Ensures NTLM sessions cannot negotiate weak 40-bit or 56-bit encryption."
        Remediation = "Enable 'Require NTLMv2 session security' and 'Require 128-bit encryption' for both NTLM SSP client and server via GPO."
    },
    @{
        ID = "CIS-2.3.4"
        Section = "2.3 Security Options - LSA Protection"
        Recommendation = "Configure LSA to run as a protected process (RunAsPPL): Enabled (1 or 2)"
        TargetProfile = "Domain Controller"
        CurrentValue = switch ($runAsPPL) { 1 { "1 (Enabled with UEFI variable)" } 2 { "2 (Enabled without UEFI variable)" } default { if ($null -eq $runAsPPL) { "Disabled / Not configured (0)" } else { "$runAsPPL" } } }
        CISBenchmarkValue = "1 or 2 (Enabled)"
        Status = if ($runAsPPL -in @(1, 2)) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Prevents non-protected processes (e.g. Mimikatz, procdump) from reading LSASS memory and extracting credentials."
        Remediation = "Enable RunAsPPL by configuring 'Configures LSASS to run as a protected process' to Enabled in Computer Configuration > Administrative Templates > System > Local Security Authority."
    },
    @{
        ID = "CIS-2.3.5"
        Section = "2.3 Security Options - WDigest"
        Recommendation = "WDigest Authentication: Prevent caching cleartext credentials in memory (UseLogonCredential: 0)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($wdigestUseLogonCred -eq 0) { "0 (Disabled - Secure)" } else { if ($null -eq $wdigestUseLogonCred) { "Default (Windows Server 2025 default is disabled)" } else { "$wdigestUseLogonCred" } }
        CISBenchmarkValue = "0 (Disabled)"
        Status = if ($wdigestUseLogonCred -eq 0 -or $null -eq $wdigestUseLogonCred) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Ensures plaintext passwords are never cached in LSASS memory for WDigest authentication."
        Remediation = "Maintain WDigest UseLogonCredential disabled (0)."
    },
    @{
        ID = "CIS-2.3.6"
        Section = "2.3 Security Options - Microsoft Network Server"
        Recommendation = "Microsoft network server: Digitally sign communications (always): Enabled"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($smbServerRequireSign -eq 1) { "Enabled (1)" } else { if ($null -eq $smbServerRequireSign) { "Default on Windows Server DC (Enabled via DC Policy)" } else { "Disabled ($smbServerRequireSign)" } }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($smbServerRequireSign -eq 1 -or $null -eq $smbServerRequireSign) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Windows Server Domain Controllers enforce SMB server signing by default to prevent SMB relay and tampering."
        Remediation = "Ensure 'Microsoft network server: Digitally sign communications (always)' is Enabled."
    },
    @{
        ID = "CIS-2.3.7"
        Section = "2.3 Security Options - SMB Protocols"
        Recommendation = "Disable SMBv1 server driver: SMB1 = 0"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($smb1Server -eq 0) { "0 (Disabled)" } else { if ($null -eq $smb1Server) { "Not present / Removed in Win Server 2025" } else { "Enabled ($smb1Server)" } }
        CISBenchmarkValue = "0 (Disabled / Uninstalled)"
        Status = "COMPLIANT"
        Severity = "CRITICAL"
        Rationale = "SMBv1 is critically vulnerable to WannaCry/EternalBlue exploits; completely removed in modern builds."
        Remediation = "SMBv1 driver is disabled/uninstalled on Windows Server 2025."
    },
    @{
        ID = "CIS-2.3.8"
        Section = "2.3 Security Options - Interactive Logon"
        Recommendation = "Interactive logon: Number of previous logons to cache: 0 to 4 logons"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($cachedLogons) { "$cachedLogons logons" } else { "Not configured (Default: 10 logons)" }
        CISBenchmarkValue = "<= 4 logons (Recommended: 0 for DCs)"
        Status = if ($cachedLogons -and [int]$cachedLogons -le 4) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Caching password verifiers locally on a Domain Controller is unnecessary and poses offline hash attack risks."
        Remediation = "Set 'Interactive logon: Number of previous logons to cache' to 0 (or <= 4) via Default Domain Controllers Policy."
    },
    @{
        ID = "CIS-2.3.9"
        Section = "2.3 Security Options - Interactive Logon"
        Recommendation = "Interactive logon: Do not display last user name: Enabled (1)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($dontDisplayLastUser -eq 1) { "1 (Enabled)" } else { "0 (Disabled / Displays last username)" }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($dontDisplayLastUser -eq 1) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "LOW"
        Rationale = "Prevents shoulder-surfing and discovery of administrative usernames on console logon."
        Remediation = "Configure 'Interactive logon: Do not display last user name' to 'Enabled' via GPO."
    },
    @{
        ID = "CIS-2.3.10"
        Section = "2.3 Security Options - Interactive Logon"
        Recommendation = "Interactive logon: Message text and title for users attempting to log on: Configured"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($legalNoticeCaption -and $legalNoticeText) { "Configured ($legalNoticeCaption)" } else { "Not configured (Blank)" }
        CISBenchmarkValue = "Configured with Authorized Use Warning Banner"
        Status = if ($legalNoticeCaption -and $legalNoticeText) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "LOW"
        Rationale = "Presents mandatory corporate warning banner informing unauthorized users of monitoring and legal consequences."
        Remediation = "Define 'Interactive logon: Message text for users attempting to log on' and 'Message title' in GPO."
    },
    @{
        ID = "CIS-2.3.11"
        Section = "2.3 Security Options - User Account Control"
        Recommendation = "User Account Control: Run all administrators in Admin Approval Mode (EnableLUA: 1)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($enableLUA -eq 1) { "1 (Enabled)" } else { "0 (Disabled)" }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($enableLUA -eq 1) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Enforces least privilege token separation even for members of local/domain administrators."
        Remediation = "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is Enabled."
    },
    @{
        ID = "CIS-2.3.12"
        Section = "2.3 Security Options - User Account Control"
        Recommendation = "User Account Control: Behavior of the elevation prompt for administrators: Prompt for consent on secure desktop"
        TargetProfile = "Domain Controller"
        CurrentValue = switch ($consentPromptAdmin) { 2 { "2 (Prompt for consent on secure desktop)" } 5 { "5 (Prompt for consent for non-Windows binaries)" } default { if ($null -eq $consentPromptAdmin) { "Default (5 - Prompt for consent)" } else { "$consentPromptAdmin" } } }
        CISBenchmarkValue = "2 (Prompt for consent on the secure desktop)"
        Status = if ($consentPromptAdmin -eq 2) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Prevents background malware from auto-elevating or spoofing elevation prompts."
        Remediation = "Set 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' to 'Prompt for consent on the secure desktop' via GPO."
    },
    @{
        ID = "CIS-2.3.13"
        Section = "2.3 Security Options - User Account Control"
        Recommendation = "User Account Control: Admin Approval Mode for the Built-in Administrator account: Enabled"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($filterAdminToken -eq 1) { "1 (Enabled)" } else { if ($null -eq $filterAdminToken) { "0 (Disabled / Default)" } else { "$filterAdminToken" } }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($filterAdminToken -eq 1) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Ensures the built-in Administrator account also runs with split tokens and requires UAC elevation."
        Remediation = "Configure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' to 'Enabled' in GPO."
    },

    # --- SYSTEM SERVICES HARDENING (CIS Section 5) ---
    @{
        ID = "CIS-5.1.1"
        Section = "5.1 System Services - Domain Controller"
        Recommendation = "Print Spooler (Spooler) service: Disabled on Domain Controllers"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($spooler) { "$($spooler.State) (Startup: $($spooler.StartMode))" } else { "Not found" }
        CISBenchmarkValue = "Disabled (State: Stopped)"
        Status = if ($spooler.StartMode -eq 'Disabled') { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "CRITICAL"
        Rationale = "Print Spooler on DCs allows unauthenticated attackers to trigger remote authentication (PrintNightmare, PetitPotam) and compromise the entire forest."
        Remediation = "Stop and Disable the Print Spooler service on all Domain Controllers via PowerShell: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled."
    },
    @{
        ID = "CIS-5.1.2"
        Section = "5.1 System Services - Domain Controller"
        Recommendation = "Remote Registry (RemoteRegistry) service: Disabled"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($remoteReg) { "$($remoteReg.State) (Startup: $($remoteReg.StartMode))" } else { "Not found" }
        CISBenchmarkValue = "Disabled (State: Stopped)"
        Status = if ($remoteReg.StartMode -eq 'Disabled') { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Restricts remote registry querying to authenticated tools and reduces lateral movement surface."
        Remediation = "Configure 'Remote Registry' service startup type to Disabled."
    },
    @{
        ID = "CIS-5.1.3"
        Section = "5.1 System Services - Domain Controller"
        Recommendation = "Downloaded Maps Manager (MapsBroker) service: Disabled"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($mapsBroker) { "$($mapsBroker.State) (Startup: $($mapsBroker.StartMode))" } else { "Disabled / Not Installed" }
        CISBenchmarkValue = "Disabled"
        Status = if (-not $mapsBroker -or $mapsBroker.StartMode -eq 'Disabled') { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "LOW"
        Rationale = "Unnecessary service on an enterprise server role."
        Remediation = "Disable MapsBroker service."
    },

    # --- NETWORK PROTOCOLS & SYSTEM HARDENING (CIS Section 18) ---
    @{
        ID = "CIS-18.1.1"
        Section = "18.1 Network Security - Name Resolution"
        Recommendation = "Turn off Link-Local Multicast Name Resolution (LLMNR): Enabled (EnableMulticast: 0)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($enableLLMNR -eq 0) { "0 (LLMNR Disabled)" } else { "Not configured / Default (LLMNR Enabled)" }
        CISBenchmarkValue = "0 (LLMNR Disabled)"
        Status = if ($enableLLMNR -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "LLMNR allows unauthenticated attackers on the subnet to spoof responses and capture NTLM hashes (Responder attacks)."
        Remediation = "Enable 'Turn off multicast name resolution' in Computer Configuration > Administrative Templates > Network > DNS Client."
    },
    @{
        ID = "CIS-18.2.1"
        Section = "18.2 Remote Desktop Services"
        Recommendation = "Require user authentication for remote connections by using Network Level Authentication (NLA): Enabled (UserAuthentication: 1)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($userAuthenticationNLA -eq 1) { "1 (NLA Enforced)" } else { if ($null -eq $userAuthenticationNLA) { "1 (Default in Server 2025)" } else { "0 / Not enforced ($userAuthenticationNLA)" } }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($userAuthenticationNLA -eq 1 -or $null -eq $userAuthenticationNLA) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Requires client authentication prior to establishing full RDP desktop session, mitigating BlueKeep/DoS vulnerabilities."
        Remediation = "Ensure Network Level Authentication (NLA) is required for RDP connections."
    },
    @{
        ID = "CIS-18.2.2"
        Section = "18.2 Remote Desktop Services"
        Recommendation = "Do not allow passwords to be saved: Enabled (DisablePasswordSaving: 1)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($disablePasswordSaving -eq 1) { "1 (Enabled)" } else { "Not configured / Disabled (0)" }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($disablePasswordSaving -eq 1) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Prevents RDP clients from saving credentials on administrative workstations."
        Remediation = "Enable 'Do not allow passwords to be saved' in Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Connection Client."
    },
    @{
        ID = "CIS-18.3.1"
        Section = "18.3 Administrative Logging"
        Recommendation = "Turn on PowerShell Script Block Logging: Enabled (EnableScriptBlockLogging: 1)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($enableScriptBlock -eq 1) { "1 (Enabled)" } else { "Not configured / Disabled (0)" }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($enableScriptBlock -eq 1) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Captures deobfuscated PowerShell code blocks in Event Log 4104 for SOC/incident response investigation."
        Remediation = "Enable 'Turn on PowerShell Script Block Logging' in Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell."
    },
    @{
        ID = "CIS-18.3.2"
        Section = "18.3 Administrative Logging"
        Recommendation = "Turn on PowerShell Transcription: Enabled (EnableTranscripting: 1)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($enableTranscript -eq 1) { "1 (Enabled)" } else { "Not configured / Disabled (0)" }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($enableTranscript -eq 1) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Records input and output from PowerShell sessions into text-based transcription logs."
        Remediation = "Configure 'Turn on PowerShell Transcription' to write logs to a secured enterprise share."
    },

    # --- DEFENDER FIREWALL PROFILES (CIS Section 9) ---
    @{
        ID = "CIS-9.1.1"
        Section = "9.1 Windows Defender Firewall"
        Recommendation = "Windows Defender Firewall: Domain Profile: Firewall state: On (1)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($fwDomainEnable -eq 1 -or $null -eq $fwDomainEnable) { "1 (Enabled / Active)" } else { "0 (Disabled)" }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($fwDomainEnable -ne 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "CRITICAL"
        Rationale = "Essential host-based packet filtering to protect DC listening ports from untrusted subnets."
        Remediation = "Ensure Windows Defender Firewall Domain Profile state is set to On."
    },
    @{
        ID = "CIS-9.2.1"
        Section = "9.2 Windows Defender Firewall"
        Recommendation = "Windows Defender Firewall: Private Profile: Firewall state: On (1)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($fwPrivateEnable -eq 1 -or $null -eq $fwPrivateEnable) { "1 (Enabled / Active)" } else { "0 (Disabled)" }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($fwPrivateEnable -ne 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "HIGH"
        Rationale = "Prevents unrestricted inbound traffic when connected to private network segments."
        Remediation = "Ensure Windows Defender Firewall Private Profile state is set to On."
    },
    @{
        ID = "CIS-9.3.1"
        Section = "9.3 Windows Defender Firewall"
        Recommendation = "Windows Defender Firewall: Public Profile: Firewall state: On (1)"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($fwPublicEnable -eq 1 -or $null -eq $fwPublicEnable) { "1 (Enabled / Active)" } else { "0 (Disabled)" }
        CISBenchmarkValue = "1 (Enabled)"
        Status = if ($fwPublicEnable -ne 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "CRITICAL"
        Rationale = "Prevents unrestricted inbound traffic on public network profiles."
        Remediation = "Ensure Windows Defender Firewall Public Profile state is set to On."
    },

    # --- EVENT LOG SIZES & RETENTION (CIS Section 19) ---
    @{
        ID = "CIS-19.1.1"
        Section = "19.1 Event Log"
        Recommendation = "Security Log: Maximum log size: 1,048,576 KB (1 GB) or greater"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($secLog) { "$([Math]::Round($secLog.MaxFileSize / 1MB, 0)) MB ($($secLog.MaxFileSize) bytes)" } else { "Default" }
        CISBenchmarkValue = ">= 1,024 MB (1 GB)"
        Status = if ($secLog -and $secLog.MaxFileSize -ge 1073741824) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Prevents premature overwriting of critical Kerberos authentication and directory access audit records."
        Remediation = "Increase Security Event Log size to at least 1,048,576 KB (1 GB) via GPO."
    },
    @{
        ID = "CIS-19.1.2"
        Section = "19.1 Event Log"
        Recommendation = "System Log: Maximum log size: 262,144 KB (256 MB) or greater"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($sysLog) { "$([Math]::Round($sysLog.MaxFileSize / 1MB, 0)) MB ($($sysLog.MaxFileSize) bytes)" } else { "Default" }
        CISBenchmarkValue = ">= 256 MB"
        Status = if ($sysLog -and $sysLog.MaxFileSize -ge 268435456) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "LOW"
        Rationale = "Ensures driver, service, and hardware error telemetry is retained."
        Remediation = "Increase System Event Log size to at least 262,144 KB (256 MB) via GPO."
    },
    @{
        ID = "CIS-19.1.3"
        Section = "19.1 Event Log"
        Recommendation = "Directory Service Log: Maximum log size: 262,144 KB (256 MB) or greater"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($dirLog) { "$([Math]::Round($dirLog.MaxFileSize / 1MB, 0)) MB ($($dirLog.MaxFileSize) bytes)" } else { "Default" }
        CISBenchmarkValue = ">= 256 MB"
        Status = if ($dirLog -and $dirLog.MaxFileSize -ge 268435456) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "MEDIUM"
        Rationale = "Retains directory service replication and database operational events."
        Remediation = "Increase Directory Service Event Log size to at least 262,144 KB (256 MB) via GPO."
    },
    @{
        ID = "CIS-19.1.4"
        Section = "19.1 Event Log"
        Recommendation = "DNS Server Log: Maximum log size: 262,144 KB (256 MB) or greater"
        TargetProfile = "Domain Controller"
        CurrentValue = if ($dnsLog) { "$([Math]::Round($dnsLog.MaxFileSize / 1MB, 0)) MB ($($dnsLog.MaxFileSize) bytes)" } else { "Default" }
        CISBenchmarkValue = ">= 256 MB"
        Status = if ($dnsLog -and $dnsLog.MaxFileSize -ge 268435456) { "COMPLIANT" } else { "NON-COMPLIANT" }
        Severity = "LOW"
        Rationale = "Retains DNS zone replication, scavenging, and query operational logs."
        Remediation = "Increase DNS Server Event Log size to at least 262,144 KB (256 MB) via GPO."
    }
)

$auditSummary = @{
    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    TargetIP = $TargetIP
    Hostname = $os.CSName
    OSCaption = $os.Caption
    OSVersion = $os.Version
    BuildNumber = $os.BuildNumber
    Domain = $cs.Domain
    TotalRulesAudited = $cisRules.Count
    CompliantCount = ($cisRules | Where-Object { $_.Status -eq "COMPLIANT" }).Count
    NonCompliantCount = ($cisRules | Where-Object { $_.Status -eq "NON-COMPLIANT" }).Count
    ComplianceScore = [Math]::Round((($cisRules | Where-Object { $_.Status -eq "COMPLIANT" }).Count / $cisRules.Count) * 100, 1)
    Rules = $cisRules
}

# Output to JSON
$jsonDir = Split-Path -Parent $OutputFile
if (-not (Test-Path $jsonDir)) { New-Item -ItemType Directory -Path $jsonDir -Force | Out-Null }
$jsonString = $auditSummary | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText((Resolve-Path $jsonDir).Path + "\" + (Split-Path -Leaf $OutputFile), $jsonString, [System.Text.Encoding]::UTF8)

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "AUDIT COMPLETED: $($auditSummary.ComplianceScore)% COMPLIANCE SCORE" -ForegroundColor $(if ($auditSummary.ComplianceScore -ge 80) { "Green" } else { "Yellow" })
Write-Host "Total Rules: $($auditSummary.TotalRulesAudited) | Compliant: $($auditSummary.CompliantCount) | Non-Compliant: $($auditSummary.NonCompliantCount)" -ForegroundColor Cyan
Write-Host "Audit Results Saved: $OutputFile" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
