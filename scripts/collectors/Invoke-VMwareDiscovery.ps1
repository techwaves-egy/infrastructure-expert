# Discovery Collector: VMware vSphere & Virtual Infrastructure
# Read-Only Inspection - Non-Intrusive

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$vCenterServer,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "discovery\vmware\vmware_telemetry.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$vmwareData = [ordered]@{
    DiscoveryTimestamp = (Get-Date).ToString("o")
    vCenter = [ordered]@{}
    Clusters = @()
    Hosts = @()
    Datastores = @()
    SnapshotsOlderThan72h = @()
    VMAlerts = @()
    Status = "UNKNOWN"
}

# Check PowerCLI
$hasPowerCLI = Get-Module -ListAvailable VMware.VimAutomation.Core
if (-not $hasPowerCLI) {
    $vmwareData.Status = "NOT_CHECKED"
    $vmwareData.vCenter = [ordered]@{
        Message = "VMware PowerCLI module (VMware.VimAutomation.Core) is not loaded or configured."
    }
    Write-Warning "VMware.VimAutomation.Core not loaded."
} else {
    Import-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue
    
    if (-not $vCenterServer) {
        $vmwareData.Status = "NOT_CHECKED"
        $vmwareData.vCenter = [ordered]@{
            Message = "No vCenter server specified for discovery. Provide -vCenterServer parameter."
        }
    } else {
        try {
            Write-Verbose "Querying vCenter: $vCenterServer"
            # Read-only queries using active session if connected
            $vc = $global:DefaultVIServer
            if (-not $vc -or $vc.Name -ne $vCenterServer) {
                Write-Warning "Not connected to vCenter $vCenterServer. Use Connect-VIServer before running."
                $vmwareData.Status = "NOT_CONNECTED"
            } else {
                $vmwareData.vCenter = [ordered]@{
                    Name = $vc.Name
                    Version = $vc.Version
                    Build = $vc.Build
                    IsConnected = $vc.IsConnected
                }
                
                # Hosts
                $hosts = Get-VMHost -ErrorAction SilentlyContinue
                foreach ($h in $hosts) {
                    $vmwareData.Hosts += [ordered]@{
                        Name = $h.Name
                        ConnectionState = $h.ConnectionState.ToString()
                        PowerState = $h.PowerState.ToString()
                        ProcessorType = $h.ProcessorType
                        CpuTotalMhz = $h.CpuTotalMhz
                        CpuUsageMhz = $h.CpuUsageMhz
                        MemoryTotalGB = [math]::Round($h.MemoryTotalGB, 2)
                        MemoryUsageGB = [math]::Round($h.MemoryUsageGB, 2)
                        Version = $h.Version
                        Build = $h.Build
                    }
                }
                
                # Datastores
                $dsList = Get-Datastore -ErrorAction SilentlyContinue
                foreach ($ds in $dsList) {
                    $freePct = if ($ds.CapacityGB -gt 0) { [math]::Round(($ds.FreeSpaceGB / $ds.CapacityGB) * 100, 2) } else { 0 }
                    $vmwareData.Datastores += [ordered]@{
                        Name = $ds.Name
                        CapacityGB = [math]::Round($ds.CapacityGB, 2)
                        FreeSpaceGB = [math]::Round($ds.FreeSpaceGB, 2)
                        FreeSpacePct = $freePct
                        Type = $ds.FileSystemVersion
                        Status = if ($freePct -lt 15) { "WARNING" } elseif ($freePct -lt 10) { "CRITICAL" } else { "HEALTHY" }
                    }
                }
                
                # Snapshots older than 72 hours
                $cutoff = (Get-Date).AddHours(-72)
                $oldSnaps = Get-VM | Get-Snapshot -ErrorAction SilentlyContinue | Where-Object { $_.Created -lt $cutoff }
                foreach ($snap in $oldSnaps) {
                    $vmwareData.SnapshotsOlderThan72h += [ordered]@{
                        VMName = $snap.VM.Name
                        SnapshotName = $snap.Name
                        Created = $snap.Created.ToString("o")
                        AgeHours = [math]::Round(((Get-Date) - $snap.Created).TotalHours, 1)
                        SizeGB = [math]::Round($snap.SizeGB, 2)
                    }
                }
                $vmwareData.Status = "HEALTHY"
            }
        } catch {
            $vmwareData.Status = "ERROR"
            $vmwareData.vCenter = [ordered]@{ Error = $_.ToString() }
        }
    }
}

$outputDir = Split-Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$vmwareData | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Output "[OK] VMware telemetry saved to: $OutputPath"
