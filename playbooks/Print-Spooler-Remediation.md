# Print Spooler Hardening on Domain Controllers (CVE-2021-34527)

## 1. Problem Statement
Running the Print Spooler service (`Spooler`) on Active Directory Domain Controllers exposes the directory tier to critical remote code execution and privilege escalation attacks (PrintNightmare, PetitPotam unconstrained delegation relay). CIS Microsoft Windows Server Benchmark explicitly requires stopping and disabling `Spooler` on all DCs.

---

## 2. Detection Query
```powershell
Get-Service -Name Spooler | Select-Object Name, Status, StartType
```

---

## 3. Remediation Script
```powershell
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```

---

## 4. Rollback Script
```powershell
Set-Service -Name Spooler -StartupType Automatic
Start-Service -Name Spooler
```

---

## 5. Post-Remediation Validation
```powershell
$svc = Get-Service -Name Spooler
if ($svc.Status -eq 'Stopped' -and $svc.StartType -eq 'Disabled') {
    Write-Host "[SUCCESS] Print Spooler successfully disabled." -ForegroundColor Green
} else {
    Write-Error "[FAIL] Print Spooler state is still $($svc.Status) / $($svc.StartType)"
}
```
