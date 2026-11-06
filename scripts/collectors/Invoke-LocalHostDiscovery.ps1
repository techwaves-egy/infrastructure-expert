# Discovery Collector: Local Host Health & Telemetry
# Read-Only Inspection - Non-Intrusive

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "discovery\windows\localhost_telemetry.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Write-Verbose "Starting Read-Only Local Host Discovery..."

$telemetry = [ordered]@{
    DiscoveryTimestamp = (Get-Date).ToString("o")
    HostInfo = [ordered]@{}
    OperatingSystem = [ordered]@{}
    Hardware = [ordered]@{}
    Storage = @()
    Network = @()
    RolesAndFeatures = @()
    Services = [ordered]@{}
    PendingReboot = [ordered]@{}
    WindowsUpdate = [ordered]@{}
    TimeSync = [ordered]@{}
    Firewall = @()
    SecurityControls = [ordered]@{}
    EventLogSummary = [ordered]@{}
    Certificates = @()
    ResourceUtilization = [ordered]@{}
}

# 1. Host Info & Operating System
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    
    $telemetry.HostInfo = [ordered]@{
        Hostname = $env:COMPUTERNAME
        Domain = if ($cs) { $cs.Domain } else { "WORKGROUP" }
        PartOfDomain = if ($cs) { $cs.PartOfDomain } else { $false }
        Manufacturer = if ($cs) { $cs.Manufacturer } else { "N/A" }
        Model = if ($cs) { $cs.Model } else { "N/A" }
    }

    $telemetry.OperatingSystem = [ordered]@{
        Caption = if ($os) { $os.Caption } else { [System.Environment]::OSVersion.VersionString }
        Version = if ($os) { $os.Version } else { "N/A" }
        BuildNumber = if ($os) { $os.BuildNumber } else { "N/A" }
        InstallDate = if ($os) { $os.InstallDate } else { "N/A" }
        LastBootUpTime = if ($os) { $os.LastBootUpTime } else { "N/A" }
        UptimeDays = if ($os -and $os.LastBootUpTime) { [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2) } else { 0 }
    }
} catch {
    Write-Warning "Failed collecting OS information: $_"
}

# 2. Hardware: CPU & Memory
try {
    $proc = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $telemetry.Hardware = [ordered]@{
        ProcessorName = if ($proc) { $proc.Name.Trim() } else { "N/A" }
        NumberOfCores = if ($proc) { $proc.NumberOfCores } else { 0 }
        NumberOfLogicalProcessors = if ($proc) { $proc.NumberOfLogicalProcessors } else { 0 }
        TotalPhysicalMemoryGB = if ($cs -and $cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { 0 }
        FreePhysicalMemoryGB = if ($os -and $os.FreePhysicalMemory) { [math]::Round($os.FreePhysicalMemory / 1MB, 2) } else { 0 }
    }
} catch {
    Write-Warning "Failed collecting Hardware info: $_"
}

# 3. Storage
try {
    $volumes = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -ne $null -and $_.Size -gt 0 }
    foreach ($vol in $volumes) {
        $freePct = if ($vol.Size -gt 0) { [math]::Round(($vol.SizeRemaining / $vol.Size) * 100, 2) } else { 0 }
        $telemetry.Storage += [ordered]@{
            DriveLetter = "$($vol.DriveLetter):"
            FileSystemLabel = $vol.FileSystemLabel
            FileSystem = $vol.FileSystem
            SizeGB = [math]::Round($vol.Size / 1GB, 2)
            FreeSpaceGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
            FreeSpacePct = $freePct
            HealthStatus = $vol.HealthStatus
            Status = if ($freePct -lt 10) { "CRITICAL" } elseif ($freePct -lt 15) { "WARNING" } else { "HEALTHY" }
        }
    }
} catch {
    Write-Warning "Failed collecting Storage: $_"
}

# 4. Network
try {
    $nics = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4Address -ne $null }
    foreach ($nic in $nics) {
        $telemetry.Network += [ordered]@{
            InterfaceAlias = $nic.InterfaceAlias
            IPv4Address = ($nic.IPv4Address.IPAddress -join ', ')
            IPv4DefaultGateway = if ($nic.IPv4DefaultGateway) { ($nic.IPv4DefaultGateway.NextHop -join ', ') } else { "None" }
            DNSServers = ($nic.DNSServer.ServerAddresses -join ', ')
            NetAdapterStatus = $nic.NetAdapter.Status
            LinkSpeed = $nic.NetAdapter.LinkSpeed
        }
    }
} catch {
    Write-Warning "Failed collecting Network info: $_"
}

# 5. Services (Failed / Auto-start Stopped)
try {
    $autoStopped = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' -and $_.Name -notmatch '(?i)edgeupdate|cdpusersvc|OneSyncSvc|WbioSrvc|MapsBroker' }
    $telemetry.Services = [ordered]@{
        TotalServices = (Get-Service).Count
        RunningServices = (Get-Service | Where-Object { $_.Status -eq 'Running' }).Count
        StoppedAutoStartCount = ($autoStopped | Measure-Object).Count
        FailedAutoServices = ($autoStopped | Select-Object -Property Name, DisplayName, Status, StartType)
    }
} catch {
    Write-Warning "Failed collecting Service status: $_"
}

# 6. Pending Reboot Assessment
try {
    $cbsReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $wuReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    $fileRename = $false
    $smProps = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue
    if ($smProps -and ($smProps.PSObject.Properties.Name -contains "PendingFileRenameOperations")) {
        $fileRename = $smProps.PendingFileRenameOperations -ne $null
    }
    
    $isRebootPending = [bool]($cbsReboot -or $wuReboot -or $fileRename)
    $telemetry.PendingReboot = [ordered]@{
        IsPendingReboot = $isRebootPending
        CBSRebootPending = [bool]$cbsReboot
        WindowsUpdateRebootRequired = [bool]$wuReboot
        PendingFileRename = [bool]$fileRename
        Status = if ($isRebootPending) { "WARNING" } else { "HEALTHY" }
    }
} catch {
    Write-Warning "Failed evaluating Pending Reboot: $_"
}

# 7. Time Sync / NTP
try {
    $w32tm = & w32tm /query /status 2>&1
    $sourceLine = ($w32tm | Select-String "Source:") -replace "Source:\s*", ""
    $telemetry.TimeSync = [ordered]@{
        TimeSource = if ($sourceLine) { $sourceLine.Trim() } else { "Local CMOS / Unspecified" }
        ServiceStatus = (Get-Service -Name "w32time" -ErrorAction SilentlyContinue).Status
    }
} catch {
    Write-Warning "Failed querying time synchronization: $_"
}

# 8. Firewall Status
try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    foreach ($prof in $fwProfiles) {
        $telemetry.Firewall += [ordered]@{
            Profile = $prof.Name
            Enabled = $prof.Enabled
            DefaultInboundAction = $prof.DefaultInboundAction
            DefaultOutboundAction = $prof.DefaultOutboundAction
        }
    }
} catch {
    Write-Warning "Failed collecting Firewall status: $_"
}

# 9. Antivirus / EDR
try {
    $avInfo = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
    if ($avInfo) {
        $telemetry.SecurityControls = [ordered]@{
            DisplayName = ($avInfo.displayName -join '; ')
            ProductState = ($avInfo.productState -join '; ')
            Status = "HEALTHY"
        }
    } else {
        $telemetry.SecurityControls = [ordered]@{
            DisplayName = "Defender / Built-in or Not Detectable via SecurityCenter2"
            Status = "INFO"
        }
    }
} catch {
    $telemetry.SecurityControls = [ordered]@{ Status = "UNKNOWN" }
}

# 10. Event Log Errors / Warnings (Past 24 Hours)
try {
    $cutoff = (Get-Date).AddHours(-24)
    $sysErrors = (Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=$cutoff} -ErrorAction SilentlyContinue | Measure-Object).Count
    $appErrors = (Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=$cutoff} -ErrorAction SilentlyContinue | Measure-Object).Count
    
    $telemetry.EventLogSummary = [ordered]@{
        PastHours = 24
        SystemCriticalAndErrors = $sysErrors
        ApplicationCriticalAndErrors = $appErrors
        Status = if ($sysErrors -gt 50 -or $appErrors -gt 100) { "WARNING" } else { "HEALTHY" }
    }
} catch {
    Write-Warning "Failed querying Event Logs: $_"
}

# Output to JSON
$outputDir = Split-Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$telemetry | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Output "[OK] Local host telemetry saved to: $OutputPath"
