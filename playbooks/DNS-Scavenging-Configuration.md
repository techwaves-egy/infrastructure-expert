# DNS Aging and Scavenging Configuration Playbook

## 1. Objective & Scope
Stale resource records in Active Directory-integrated DNS zones cause name resolution failures, IP collisions, and Kerberos ticket delegation errors. This playbook configures automatic scavenging across zones and DNS server instances.

---

## 2. Detection
```powershell
Get-DnsServerScavenging
Get-DnsServerZoneAging -Name "<ZoneName>"
```

---

## 3. Remediation Script
```powershell
# 1. Enable server-level scavenging (every 7 days / 168 hours)
Set-DnsServerScavenging -ScavengingInterval (New-TimeSpan -Days 7)

# 2. Enable zone-level aging and scavenging
Set-DnsServerZoneAging -Name "<ZoneName>" -Aging $true -NoRefreshInterval (New-TimeSpan -Days 7) -RefreshInterval (New-TimeSpan -Days 7)
```

---

## 4. Rollback Script
```powershell
Set-DnsServerScavenging -ScavengingInterval (New-TimeSpan -Days 0)
Set-DnsServerZoneAging -Name "<ZoneName>" -Aging $false
```

---

## 5. Post-Remediation Validation
```powershell
$srv = Get-DnsServerScavenging
$zone = Get-DnsServerZoneAging -Name "<ZoneName>"
Write-Host "Server Scavenging Interval: $($srv.ScavengingInterval)"
Write-Host "Zone Aging Enabled: $($zone.AgingEnabled)"
```
