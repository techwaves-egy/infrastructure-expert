# Discovery Collector: Active Directory, DNS & DHCP Health
# Read-Only Inspection - Non-Intrusive

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "discovery\ad_ds\ad_dns_telemetry.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$adData = [ordered]@{
    DiscoveryTimestamp = (Get-Date).ToString("o")
    DomainContext = [ordered]@{}
    DomainControllers = @()
    FSMORoles = [ordered]@{}
    ReplicationSummary = @()
    DNSConfiguration = [ordered]@{}
    DHCPSummary = [ordered]@{}
    ErrorsAndWarnings = @()
}

$hasADModule = Get-Module -ListAvailable ActiveDirectory
if (-not $hasADModule) {
    $adData.DomainContext = [ordered]@{
        Status = "NOT_CHECKED"
        Message = "ActiveDirectory PowerShell module (RSAT) is not installed on the local system."
    }
    Write-Warning "ActiveDirectory module not available."
} else {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    try {
        $dom = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop
        
        $adData.DomainContext = [ordered]@{
            DomainName = $dom.DNSRoot
            NetBIOSName = $dom.NetBIOSName
            DomainMode = $dom.DomainMode.ToString()
            ForestMode = $forest.ForestMode.ToString()
            DomainControllersCount = $dom.ReplicaDirectoryServers.Count
            Status = "HEALTHY"
        }
        
        $adData.FSMORoles = [ordered]@{
            SchemaMaster = $forest.SchemaMaster
            DomainNamingMaster = $forest.DomainNamingMaster
            PDC = $dom.PDCEmulator
            RIDMaster = $dom.RIDMaster
            InfrastructureMaster = $dom.InfrastructureMaster
        }
        
        $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
        foreach ($dc in $dcs) {
            $adData.DomainControllers += [ordered]@{
                HostName = $dc.HostName
                IPv4Address = $dc.IPv4Address
                Site = $dc.Site
                OperatingSystem = $dc.OperatingSystem
                IsGlobalCatalog = $dc.IsGlobalCatalog
                Enabled = $dc.Enabled
            }
        }
        
        # Replication status
        $replMeta = & repadmin /replsummary 2>&1
        $adData.ReplicationSummary = $replMeta
    } catch {
        $adData.DomainContext = [ordered]@{
            Status = "WARNING"
            Message = "Unable to contact Domain: $_"
        }
    }
}

# DNS Test
try {
    $dnsTest = Resolve-DnsName -Name $env:USERDNSDOMAIN -ErrorAction SilentlyContinue
    $adData.DNSConfiguration = [ordered]@{
        UserDnsDomain = $env:USERDNSDOMAIN
        ResolvedIPs = ($dnsTest.IPAddress -join ', ')
        Status = if ($dnsTest) { "HEALTHY" } else { "WARNING" }
    }
} catch {
    $adData.DNSConfiguration = [ordered]@{ Status = "UNKNOWN" }
}

$outputDir = Split-Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$adData | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Output "[OK] AD/DNS telemetry saved to: $OutputPath"
