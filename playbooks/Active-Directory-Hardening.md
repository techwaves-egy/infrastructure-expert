# Active Directory Security Hardening Playbook

## 1. Objective & Scope
Hardens enterprise Active Directory Domain Services against credential dumping, relay attacks, and unauthorized object recovery:
- Enforce LDAP Server Signing (Level 2 - Require Signature)
- Enforce LDAP Channel Binding (Level 2 - Always)
- Enable Active Directory Recycle Bin
- Map missing IP subnets in Active Directory Sites and Services
- Populate Protected Users security group

---

## 2. LDAP Server Signing Enforcement
### Remediation:
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord
```
### Rollback:
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 1 -Type DWord
```

---

## 3. LDAP Channel Binding Enforcement
### Remediation:
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
```
### Rollback:
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 1 -Type DWord
```

---

## 4. Enable Active Directory Recycle Bin
### Remediation:
```powershell
Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).RootDomain -Confirm:$false
```
*(Note: Active Directory Recycle Bin is irreversible by design in AD architecture).*

---

## 5. Active Directory Subnet Mapping
### Remediation:
```powershell
New-ADReplicationSubnet -Name "<SubnetCIDR>" -Site "Default-First-Site-Name"
```
### Rollback:
```powershell
Remove-ADReplicationSubnet -Identity "<SubnetCIDR>" -Confirm:$false
```
