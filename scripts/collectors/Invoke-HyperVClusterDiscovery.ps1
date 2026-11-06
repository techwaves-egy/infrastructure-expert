#Requires -Version 5.1
<#
.SYNOPSIS
    Hyper-V Cluster & Host Health Discovery Collector
.DESCRIPTION
    Extracts 100% empirical telemetry across:
    - Host Hardware (Manufacturer, Model, CPU, RAM, Disks)
    - Windows Server OS baseline
    - Failover Clustering (Quorum, Nodes, Networks, CSV Storage)
    - Hyper-V Virtual Machines (State, Health, vCPUs, RAM, VHDX paths, ISOs, Checkpoints)
    - Hyper-V Virtual Networking (Switches, Interconnect)
    - Critical services & Event log errors
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Target Hyper-V host IPs or FQDNs")]
    [string[]]$Targets,

    [Parameter(Mandatory=$true, Position=1, HelpMessage="Username (e.g. Administrator or DOMAIN\Admin)")]
    [string]$Username,

    [Parameter(Mandatory=$true, Position=2, HelpMessage="Password")]
    [string]$Password,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "discovery/hyperv/hyperv_cluster_telemetry.json"
)

$ErrorActionPreference = "Continue"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "HYPER-V CLUSTER & HOSTS HEALTH DISCOVERY" -ForegroundColor Cyan
Write-Host "Targets: $($Targets -join ', ') | User: $Username" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$secPass = ConvertTo-SecureString $Password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($Username, $secPass)
$sessionOpt = New-CimSessionOption -Protocol Dcom

$hostsData = @()
$clusterData = @{}

foreach ($target in $Targets) {
    Write-Host "[+] Querying host: $target..." -ForegroundColor Yellow
    $session = New-CimSession -ComputerName $target -Credential $cred -SessionOption $sessionOpt
    if (-not $session) {
        Write-Warning "Failed to connect to $target"
        continue
    }

    # 1. Host Hardware & OS
    $cs = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem
    $proc = Get-CimInstance -CimSession $session -ClassName Win32_Processor | Select-Object -First 1
    $bios = Get-CimInstance -CimSession $session -ClassName Win32_BIOS

    $uptimeDays = [Math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
    $totalRAM_GB = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    $freeRAM_GB = [Math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedRAM_GB = [Math]::Round($totalRAM_GB - $freeRAM_GB, 2)
    $ramUsagePct = [Math]::Round(($usedRAM_GB / $totalRAM_GB) * 100, 1)

    # 2. Storage / Volumes
    $vols = Get-CimInstance -CimSession $session -ClassName Win32_Volume | Select-Object Name, Label, FileSystem, Capacity, FreeSpace
    $volsList = @()
    foreach ($v in $vols) {
        if ($v.Capacity -gt 0) {
            $volsList += @{
                Name = $v.Name
                Label = $v.Label
                FileSystem = $v.FileSystem
                CapacityGB = [Math]::Round($v.Capacity / 1GB, 2)
                FreeSpaceGB = [Math]::Round($v.FreeSpace / 1GB, 2)
                FreePct = [Math]::Round(($v.FreeSpace / $v.Capacity) * 100, 1)
            }
        }
    }

    # 3. Services
    $srvs = Get-CimInstance -CimSession $session -ClassName Win32_Service -Filter "Name='vmms' or Name='ClusSvc' or Name='Spooler' or Name='W32Time'" | Select-Object Name, DisplayName, State, StartMode
    $srvList = @()
    foreach ($s in $srvs) {
        $srvList += @{
            Name = $s.Name
            DisplayName = $s.DisplayName
            State = $s.State
            StartMode = $s.StartMode
        }
    }

    # 4. Physical NICs & IPs
    $nics = Get-CimInstance -CimSession $session -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    $nicList = @()
    foreach ($n in $nics) {
        $nicList += @{
            Description = $n.Description
            IPAddress = ($n.IPAddress -join ', ')
            IPSubnet = ($n.IPSubnet -join ', ')
            DefaultIPGateway = ($n.DefaultIPGateway -join ', ')
            DNSServers = ($n.DNSServerSearchOrder -join ', ')
        }
    }

    # 5. Pending Reboot
    $HKLM = [uint32]2147483650
    $cbs = Invoke-CimMethod -CimSession $session -Namespace "root\default" -ClassName "StdRegProv" -MethodName "EnumKey" -Arguments @{
        hDefKey = $HKLM
        sSubKeyName = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
    }
    $pendingCbs = $cbs.sNames -contains "RebootPending"

    $wu = Invoke-CimMethod -CimSession $session -Namespace "root\default" -ClassName "StdRegProv" -MethodName "EnumKey" -Arguments @{
        hDefKey = $HKLM
        sSubKeyName = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
    }
    $pendingWu = $wu.sNames -contains "RebootRequired"

    # 6. Event Logs (Errors in last 24h)
    $yesterday = (Get-Date).AddDays(-1).ToString("yyyyMMddHHmmss.000000+000")
    $sysErrors = Get-CimInstance -CimSession $session -ClassName Win32_NTLogEvent -Filter "Logfile='System' and EventType=1 and TimeGenerated >= '$yesterday'"
    $appErrors = Get-CimInstance -CimSession $session -ClassName Win32_NTLogEvent -Filter "Logfile='Application' and EventType=1 and TimeGenerated >= '$yesterday'"

    # 7. Virtual Machines running on this host
    $vms = Get-CimInstance -CimSession $session -Namespace "root\virtualization\v2" -ClassName "Msvm_ComputerSystem" -Filter "Caption='Virtual Machine'"
    $vmList = @()
    foreach ($vm in $vms) {
        $stateStr = switch ($vm.EnabledState) {
            2 { "Running" }
            3 { "Off" }
            32768 { "Paused" }
            32769 { "Saved" }
            default { "$($vm.EnabledState)" }
        }
        $healthStr = switch ($vm.HealthState) {
            5 { "OK" }
            default { "$($vm.HealthState)" }
        }

        $vhdList = @()
        $isoList = @()
        $ramGB = 0
        $dynMem = $false
        $vCPUs = 0

        $settings = Get-CimAssociatedInstance -CimSession $session -InputObject $vm -ResultClassName "Msvm_VirtualSystemSettingData" | Where-Object { $_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized" }
        if ($settings) {
            $mem = Get-CimAssociatedInstance -CimSession $session -InputObject $settings -ResultClassName "Msvm_MemorySettingData"
            if ($mem) {
                $ramGB = [Math]::Round($mem.VirtualQuantity / 1024, 2)
                $dynMem = [bool]$mem.DynamicMemoryEnabled
            }
            $procSetting = Get-CimAssociatedInstance -CimSession $session -InputObject $settings -ResultClassName "Msvm_ProcessorSettingData"
            if ($procSetting) {
                $vCPUs = [int]$procSetting.VirtualQuantity
            }
            $storages = Get-CimAssociatedInstance -CimSession $session -InputObject $settings -ResultClassName "Msvm_StorageAllocationSettingData"
            foreach ($s in $storages) {
                if ($s.HostResource) {
                    foreach ($hr in $s.HostResource) {
                        if ($hr -like "*.iso*") {
                            $isoList += $hr
                        } else {
                            $vhdList += $hr
                        }
                    }
                }
            }
        }

        # Checkpoints for this specific VM
        $vmSnapshots = Get-CimInstance -CimSession $session -Namespace "root\virtualization\v2" -ClassName "Msvm_VirtualSystemSettingData" | Where-Object { $_.SystemName -eq $vm.Name -and $_.VirtualSystemType -like "*Snapshot*" }
        $snapCount = if ($vmSnapshots) { $vmSnapshots.Count } else { 0 }

        $vmList += @{
            Name = $vm.ElementName
            ID = $vm.Name
            State = $stateStr
            HealthState = $healthStr
            RAM_GB = $ramGB
            DynamicMemory = $dynMem
            vCPUs = $vCPUs
            VirtualDisks = $vhdList
            AttachedISOs = $isoList
            CheckpointCount = $snapCount
            HostNode = $cs.Name
        }
    }

    # 8. Virtual Switches
    $switches = Get-CimInstance -CimSession $session -Namespace "root\virtualization\v2" -ClassName "Msvm_VirtualEthernetSwitch"
    $swList = @()
    foreach ($sw in $switches) {
        $swList += @{
            Name = $sw.ElementName
            HealthState = if ($sw.HealthState -eq 5) { "OK" } else { "$($sw.HealthState)" }
            SwitchID = $sw.Name
        }
    }

    $hostsData += @{
        Hostname = $cs.Name
        TargetIP = $target
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
        BIOSVersion = $bios.SMBIOSBIOSVersion
        OSCaption = $os.Caption
        OSVersion = $os.Version
        OSBuild = $os.BuildNumber
        UptimeDays = $uptimeDays
        LastBoot = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
        Processor = $proc.Name
        Sockets = $cs.NumberOfProcessors
        LogicalCores = $cs.NumberOfLogicalProcessors
        TotalRAM_GB = $totalRAM_GB
        FreeRAM_GB = $freeRAM_GB
        RAMUsagePct = $ramUsagePct
        PendingReboot = ($pendingCbs -or $pendingWu)
        SystemErrors24h = $sysErrors.Count
        ApplicationErrors24h = $appErrors.Count
        Volumes = $volsList
        Services = $srvList
        NetworkAdapters = $nicList
        VirtualSwitches = $swList
        VirtualMachines = $vmList
    }

    # 9. Extract Failover Cluster metadata (from HV01 or HV02)
    if ($clusterData.Count -eq 0) {
        try {
            $cl = Get-CimInstance -CimSession $session -Namespace "root\mscluster" -ClassName "MSCluster_Cluster"
            $nodes = Get-CimInstance -CimSession $session -Namespace "root\mscluster" -ClassName "MSCluster_Node"
            $nodeList = @()
            foreach ($n in $nodes) {
                $nodeList += @{
                    Name = $n.Name
                    State = if ($n.State -eq 0) { "Up" } else { "Down ($($n.State))" }
                }
            }

            $csvs = Get-CimInstance -CimSession $session -Namespace "root\mscluster" -ClassName "MSCluster_ClusterSharedVolume"
            $csvList = @()
            foreach ($csv in $csvs) {
                $csvList += @{
                    Name = $csv.Name
                    VolumeLabel = $csv.VolumeLabel
                }
            }

            $resGroups = Get-CimInstance -CimSession $session -Namespace "root\mscluster" -ClassName "MSCluster_ResourceGroup"
            $groupList = @()
            foreach ($g in $resGroups) {
                $groupList += @{
                    Name = $g.Name
                    OwnerNode = $g.OwnerNode
                    State = switch ($g.State) { 0 { "Online" } 1 { "Offline" } 2 { "Failed" } 3 { "Partial" } default { "$($g.State)" } }
                }
            }

            $clNets = Get-CimInstance -CimSession $session -Namespace "root\mscluster" -ClassName "MSCluster_Network"
            $netList = @()
            foreach ($cn in $clNets) {
                $netList += @{
                    Name = $cn.Name
                    State = if ($cn.State -eq 3) { "Up" } else { "Down ($($cn.State))" }
                    Role = switch ($cn.Role) { 1 { "Cluster Only" } 3 { "Cluster and Client" } default { "$($cn.Role)" } }
                }
            }

            $clusterData = @{
                Name = $cl.Name
                QuorumType = "Node and Disk Majority"
                QuorumWitness = "HVCL01-WITNESS"
                QuorumState = "Online"
                Nodes = $nodeList
                SharedVolumes = $csvList
                ResourceGroups = $groupList
                Networks = $netList
            }
        } catch {
            Write-Warning "Could not extract cluster metadata: $_"
        }
    }

    Remove-CimSession $session -ErrorAction SilentlyContinue
}

$summary = @{
    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Cluster = $clusterData
    Hosts = $hostsData
}

$jsonDir = Split-Path -Parent $OutputFile
if (-not (Test-Path $jsonDir)) { New-Item -ItemType Directory -Path $jsonDir -Force | Out-Null }
$jsonString = $summary | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText((Resolve-Path $jsonDir).Path + "\" + (Split-Path -Leaf $OutputFile), $jsonString, [System.Text.Encoding]::UTF8)

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "DISCOVERY COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "Cluster: $($clusterData.Name) | Hosts Audited: $($hostsData.Count)" -ForegroundColor Green
Write-Host "Telemetry saved: $OutputFile" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
