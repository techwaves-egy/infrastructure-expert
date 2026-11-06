# Discovery Collector: Remote Host Health & Telemetry
# Safe, Non-Intrusive, Read-Only Inspection over WinRM / CIM / WMI
# Supports Remote Windows Servers, DCs, and Workstations by IP, Username, and Password

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Target IP address or FQDN")]
    [string]$TargetIP,

    [Parameter(Mandatory=$true, Position=1, HelpMessage="Username (e.g. Administrator or DOMAIN\Admin)")]
    [string]$Username,

    [Parameter(Mandatory=$true, Position=2, HelpMessage="Password for authentication")]
    [string]$Password,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Auto", "WSMan", "Dcom")]
    [string]$Protocol = "Auto",

    [Parameter(Mandatory=$false)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

if (-not $OutputPath) {
    $cleanTarget = $TargetIP -replace "[^a-zA-Z0-9\._-]", "_"
    $OutputPath = "discovery\windows\remote_${cleanTarget}_telemetry.json"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " ENTERPRISE REMOTE INFRASTRUCTURE HEALTH DISCOVERY" -ForegroundColor Cyan
Write-Host " Target IP : $TargetIP" -ForegroundColor Yellow
Write-Host " User      : $Username" -ForegroundColor Yellow
Write-Host " Protocol  : $Protocol" -ForegroundColor Yellow
Write-Host " Mode      : Strict Read-Only Assessment" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# Prepare PSCredential safely in memory
$secPass = ConvertTo-SecureString $Password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($Username, $secPass)

# Initialize Telemetry Schema
$telemetry = [ordered]@{
    DiscoveryTimestamp   = (Get-Date).ToString("o")
    TargetIP             = $TargetIP
    AuthenticationUser   = $Username
    ConnectionMethod     = "None"
    HostInfo             = [ordered]@{}
    OperatingSystem      = [ordered]@{}
    Hardware             = [ordered]@{}
    Storage              = @()
    Network              = @()
    RolesAndFeatures     = @()
    Services             = [ordered]@{}
    PendingReboot        = [ordered]@{}
    TimeSync             = [ordered]@{}
    Firewall             = @()
    SecurityControls     = [ordered]@{}
    EventLogSummary      = [ordered]@{}
    ActiveDirectoryRole  = [ordered]@{}
    ErrorsAndWarnings    = @()
    ConnectionHealth     = "FAILED"
}

# 1. Connectivity Pre-flight Test
Write-Host "[1/6] Performing network connectivity pre-flight checks on $TargetIP..." -ForegroundColor Cyan
$ping = Test-Connection -ComputerName $TargetIP -Count 2 -Quiet -ErrorAction SilentlyContinue

$winrmHttpTest = Test-NetConnection -ComputerName $TargetIP -Port 5985 -InformationLevel Quiet -WarningAction SilentlyContinue
$winrmHttpsTest = Test-NetConnection -ComputerName $TargetIP -Port 5986 -InformationLevel Quiet -WarningAction SilentlyContinue
$rpcTest = Test-NetConnection -ComputerName $TargetIP -Port 135 -InformationLevel Quiet -WarningAction SilentlyContinue
$smbTest = Test-NetConnection -ComputerName $TargetIP -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue

Write-Host "  - ICMP Echo Ping : $(if ($ping) {'REACHABLE'} else {'UNREACHABLE / FILTERED'})"
Write-Host "  - WinRM HTTP (5985) : $(if ($winrmHttpTest) {'OPEN'} else {'CLOSED / FILTERED'})"
Write-Host "  - WinRM HTTPS (5986): $(if ($winrmHttpsTest) {'OPEN'} else {'CLOSED / FILTERED'})"
Write-Host "  - RPC Endpoint (135): $(if ($rpcTest) {'OPEN'} else {'CLOSED / FILTERED'})"
Write-Host "  - SMB (445)         : $(if ($smbTest) {'OPEN'} else {'CLOSED / FILTERED'})"

# 2. Establish Remote CIM Session
Write-Host "[2/7] Negotiating remote management session..." -ForegroundColor Cyan
$cimSession = $null

# Ensure target IP is in TrustedHosts if connecting cross-domain / workgroup
try {
    $curTrusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
    if ($curTrusted -notlike "*$TargetIP*" -and $curTrusted -ne "*") {
        Write-Verbose "Adding $TargetIP to local TrustedHosts for negotiation"
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$curTrusted,$TargetIP" -Force -ErrorAction SilentlyContinue
    }
} catch {
    # Non-admin or policy restricted
}

# Determine candidate usernames (raw, domain-prefixed, UPN)
$userCandidates = @($Username)
$revDns = (Resolve-DnsName -Name $TargetIP -ErrorAction SilentlyContinue | Select-Object -First 1).NameHost
if ($Username -notmatch '[\\@]') {
    if ($revDns -and $revDns -match '([^\.]+)\.([^\.]+)$') {
        $domNetbios = $Matches[1]
        $domFqdn = "$($Matches[1]).$($Matches[2])"
        $userCandidates += "$domNetbios\$Username"
        $userCandidates += "$Username@$domFqdn"
    } elseif ($revDns -and $revDns -match '([^\.]+)\.([^\.]+)\.([^\.]+)$') {
        $domNetbios = $Matches[1]
        $domFqdn = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
        $userCandidates += "$domNetbios\$Username"
        $userCandidates += "$Username@$domFqdn"
    }
}

$userCandidates = $userCandidates | Select-Object -Unique

foreach ($userAttempt in $userCandidates) {
    if ($cimSession) { break }
    Write-Host "  [*] Attempting credentials format: $userAttempt..." -ForegroundColor Gray
    $testCred = New-Object System.Management.Automation.PSCredential($userAttempt, $secPass)
    
    # Try WSMan
    if ($Protocol -eq "Auto" -or $Protocol -eq "WSMan") {
        try {
            $opt = New-CimSessionOption -Protocol WSMan
            $cimSession = New-CimSession -ComputerName $TargetIP -Credential $testCred -SessionOption $opt -OperationTimeoutSec 10 -ErrorAction Stop
            $telemetry.ConnectionMethod = "WSMan (WinRM)"
            $telemetry.AuthenticationUser = $userAttempt
            Write-Host "  [+] Connected via CIM WSMan (WinRM) using $userAttempt." -ForegroundColor Green
            break
        } catch {
            Write-Verbose "WSMan failed for ${userAttempt}: $_"
        }
    }
    
    # Try DCOM
    if (-not $cimSession -and ($Protocol -eq "Auto" -or $Protocol -eq "Dcom")) {
        try {
            $opt = New-CimSessionOption -Protocol Dcom
            $cimSession = New-CimSession -ComputerName $TargetIP -Credential $testCred -SessionOption $opt -OperationTimeoutSec 10 -ErrorAction Stop
            $telemetry.ConnectionMethod = "DCOM (RPC/WMI)"
            $telemetry.AuthenticationUser = $userAttempt
            Write-Host "  [+] Connected via CIM DCOM (RPC) using $userAttempt." -ForegroundColor Green
            break
        } catch {
            Write-Verbose "DCOM failed for ${userAttempt}: $_"
        }
    }
}

if (-not $cimSession) {
    Write-Error "CRITICAL: Unable to establish remote CIM/WMI session to $TargetIP with provided credentials."
    $telemetry.ConnectionHealth = "FAILED"
    $telemetry.ErrorsAndWarnings += "Authentication failed for all credential candidates across WSMan and DCOM."
    
    # Save failure telemetry for reporting
    $outputDir = Split-Path $OutputPath -Parent
    if ($outputDir -and -not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    $telemetry | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding utf8
    return
}

$telemetry.ConnectionHealth = "CONNECTED"

# 3. Read-Only Query: Host Information, OS, Hardware
Write-Host "[3/7] Querying remote OS, Hardware, and System configuration..." -ForegroundColor Cyan
try {
    $cs = Get-CimInstance -CimSession $cimSession -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $proc = Get-CimInstance -CimSession $cimSession -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1

    $uptimeDays = 0
    if ($os -and $os.LastBootUpTime) {
        $uptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
    }

    $telemetry.HostInfo = [ordered]@{
        Hostname     = if ($cs) { if ($cs.DNSHostName) { $cs.DNSHostName } else { $cs.Name } } else { $TargetIP }
        Domain       = if ($cs) { $cs.Domain } else { "UNKNOWN" }
        PartOfDomain = if ($cs) { [bool]$cs.PartOfDomain } else { $false }
        Manufacturer = if ($cs) { $cs.Manufacturer } else { "N/A" }
        Model        = if ($cs) { $cs.Model } else { "N/A" }
        DomainRole   = if ($cs) { $cs.DomainRole } else { 0 }
    }

    $telemetry.OperatingSystem = [ordered]@{
        Caption        = if ($os) { $os.Caption } else { "N/A" }
        Version        = if ($os) { $os.Version } else { "N/A" }
        BuildNumber    = if ($os) { $os.BuildNumber } else { "N/A" }
        LastBootUpTime = if ($os) { $os.LastBootUpTime.ToString("o") } else { "N/A" }
        UptimeDays     = $uptimeDays
        Status         = if ($uptimeDays -gt 180) { "WARNING" } else { "HEALTHY" }
    }

    $totalRamGB = if ($cs -and $cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { 0 }
    $freeRamGB = if ($os -and $os.FreePhysicalMemory) { [math]::Round($os.FreePhysicalMemory / 1MB, 2) } else { 0 }
    $usedRamPct = if ($totalRamGB -gt 0) { [math]::Round((($totalRamGB - $freeRamGB) / $totalRamGB) * 100, 1) } else { 0 }

    $telemetry.Hardware = [ordered]@{
        ProcessorName             = if ($proc) { $proc.Name.Trim() } else { "N/A" }
        NumberOfCores             = if ($proc) { $proc.NumberOfCores } else { 0 }
        NumberOfLogicalProcessors = if ($proc) { $proc.NumberOfLogicalProcessors } else { 0 }
        TotalPhysicalMemoryGB     = $totalRamGB
        FreePhysicalMemoryGB      = $freeRamGB
        MemoryUtilizationPct      = $usedRamPct
        MemoryStatus              = if ($usedRamPct -gt 90) { "CRITICAL" } elseif ($usedRamPct -gt 80) { "WARNING" } else { "HEALTHY" }
    }
} catch {
    Write-Warning "Error during System/OS telemetry: $_"
    $telemetry.ErrorsAndWarnings += "System/OS: $_"
}

# 4. Storage & Disks
Write-Host "[4/6] Querying remote storage volumes and capacity..." -ForegroundColor Cyan
try {
    $disks = Get-CimInstance -CimSession $cimSession -ClassName Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction SilentlyContinue
    foreach ($disk in $disks) {
        $sizeGB = if ($disk.Size) { [math]::Round($disk.Size / 1GB, 2) } else { 0 }
        $freeGB = if ($disk.FreeSpace) { [math]::Round($disk.FreeSpace / 1GB, 2) } else { 0 }
        $freePct = if ($sizeGB -gt 0) { [math]::Round(($freeGB / $sizeGB) * 100, 2) } else { 0 }

        $volStatus = if ($freePct -lt 10) { "CRITICAL" } elseif ($freePct -lt 15) { "WARNING" } else { "HEALTHY" }
        $telemetry.Storage += [ordered]@{
            DriveLetter     = $disk.DeviceID
            FileSystemLabel = $disk.VolumeName
            FileSystem      = $disk.FileSystem
            SizeGB          = $sizeGB
            FreeSpaceGB     = $freeGB
            FreeSpacePct    = $freePct
            Status          = $volStatus
        }
    }
} catch {
    Write-Warning "Error during Storage telemetry: $_"
    $telemetry.ErrorsAndWarnings += "Storage: $_"
}

# 5. Network Configuration & DNS
Write-Host "[5/6] Querying remote network adapters and DNS resolvers..." -ForegroundColor Cyan
try {
    $netAdapters = Get-CimInstance -CimSession $cimSession -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction SilentlyContinue
    foreach ($nic in $netAdapters) {
        $ips = ($nic.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join ', '
        $gateways = ($nic.DefaultIPGateway -join ', ')
        $dnsServers = ($nic.DNSServerSearchOrder -join ', ')
        
        $telemetry.Network += [ordered]@{
            Description        = $nic.Description
            IPv4Address        = $ips
            IPv4DefaultGateway = if ($gateways) { $gateways } else { "None" }
            DNSServers         = if ($dnsServers) { $dnsServers } else { "None" }
            DHCPEnabled        = [bool]$nic.DHCPEnabled
        }
    }
} catch {
    Write-Warning "Error during Network telemetry: $_"
    $telemetry.ErrorsAndWarnings += "Network: $_"
}

# 6. Windows Services (Failed Automatic Services)
Write-Host "[6/6] Inspecting remote Windows Services and Service Health..." -ForegroundColor Cyan
try {
    $allServices = Get-CimInstance -CimSession $cimSession -ClassName Win32_Service -ErrorAction SilentlyContinue
    $runningCount = ($allServices | Where-Object { $_.State -eq "Running" }).Count
    
    # Identify auto-start services that are currently stopped (excluding known transient trigger services)
    $failedAuto = $allServices | Where-Object { 
        $_.StartMode -eq "Auto" -and 
        $_.State -ne "Running" -and 
        $_.Name -notmatch '(?i)edgeupdate|cdpusersvc|OneSyncSvc|WbioSrvc|MapsBroker|sppsvc|DeviceInstall' 
    }
    
    $failedList = @()
    foreach ($s in $failedAuto) {
        $failedList += [ordered]@{
            Name        = $s.Name
            DisplayName = $s.DisplayName
            State       = $s.State
            StartMode   = $s.StartMode
        }
    }
    
    $telemetry.Services = [ordered]@{
        TotalServices         = $allServices.Count
        RunningServices       = $runningCount
        StoppedAutoStartCount = $failedList.Count
        FailedAutoServices    = $failedList
        Status                = if ($failedList.Count -gt 0) { "WARNING" } else { "HEALTHY" }
    }
} catch {
    Write-Warning "Error during Services telemetry: $_"
    $telemetry.ErrorsAndWarnings += "Services: $_"
}

# 7. Active Directory & Domain Controller Health (If DC)
Write-Host "[7/7] Checking Domain Controller and Directory Service roles..." -ForegroundColor Cyan
try {
    $domainRole = if ($telemetry.HostInfo.DomainRole) { [int]$telemetry.HostInfo.DomainRole } else { 0 }
    if ($domainRole -ge 4) {
        Write-Host "  [*] Target is an Active Directory Domain Controller (Role $domainRole)." -ForegroundColor Green
        
        $shares = Get-CimInstance -CimSession $cimSession -ClassName Win32_Share -ErrorAction SilentlyContinue
        $sysvol = $shares | Where-Object { $_.Name -eq "SYSVOL" }
        $netlogon = $shares | Where-Object { $_.Name -eq "NETLOGON" }
        
        $adSvcNames = @('NTDS', 'DNS', 'Kdc', 'Netlogon', 'W32Time', 'DFSR')
        $adSvcs = @()
        if ($allServices) {
            foreach ($asName in $adSvcNames) {
                $sObj = $allServices | Where-Object { $_.Name -eq $asName }
                if ($sObj) {
                    $adSvcs += [ordered]@{
                        Name = $sObj.Name
                        State = $sObj.State
                        StartMode = $sObj.StartMode
                    }
                }
            }
        }
        
        $telemetry.ActiveDirectoryRole = [ordered]@{
            IsDomainController = $true
            SYSVOLShared       = [bool]($sysvol -ne $null)
            NETLOGONShared     = [bool]($netlogon -ne $null)
            CoreServices       = $adSvcs
            Status             = if ($sysvol -and $netlogon) { "HEALTHY" } else { "CRITICAL" }
        }
    } else {
        $telemetry.ActiveDirectoryRole = [ordered]@{
            IsDomainController = $false
            Status             = "INFO"
        }
    }
} catch {
    Write-Warning "Error during Active Directory role telemetry: $_"
    $telemetry.ErrorsAndWarnings += "AD DS: $_"
}

# Close CIM Session safely
if ($cimSession) {
    Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
}

# Persist Telemetry to JSON
$outputDir = Split-Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$telemetry | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host ""
Write-Host "[SUCCESS] Remote health telemetry collected and saved to: $OutputPath" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
