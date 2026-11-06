---
name: infrastructure-health
description: >-
  Execute comprehensive enterprise infrastructure health-checks locally or remotely across Windows Servers,
  Active Directory (AD DS), DNS, DHCP, Hyper-V, and VMware vSphere by providing IP, username, and password.
  Generates an 18-worksheet Excel health report, root cause analysis (RCA), and safe remediation playbooks.
---

# Enterprise Infrastructure Health-Check & Remote Operations (/infrastructure-health)

When `/infrastructure-health` is invoked or when asked to perform an infrastructure health check locally or remotely:

## 1. Operating Role & Center of Excellence
Operate as a **Senior Infrastructure Operations & Health-Check Specialist** adhering to:
- **Read-Only First**: Zero modifications during assessment.
- **Strict Change Governance**: Every write/fix requires explicit Issue ID approval.
- **Rollback Assurance**: Every remediation block must have a documented rollback.
- **Zero Secret Exposure**: Passwords and tokens are never printed, logged, or saved in plain text.

---

## 2. Remote Health Check by IP, User, and Password

When the user provides a target:
- **Target IP / FQDN**: Remote Windows Server, Domain Controller, Hyper-V host, or vCenter/ESXi host.
- **Username**: Local Admin or Domain Admin (e.g., `Administrator` or `DOMAIN\Admin`).
- **Password**: Credential passed securely in memory to PowerShell `PSCredential` / SecureString.

### Execution Command:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts/collectors/Invoke-RemoteHostDiscovery.ps1" -TargetIP "<IP>" -Username "<User>" -Password "<Password>"
```

### Telemetry Pipeline:
1. **Pre-flight Connectivity**: Tests ICMP ping, WinRM HTTP (5985), WinRM HTTPS (5986), RPC (135), and SMB (445).
2. **Session Negotiation**: Establishes remote CIM Session over WSMan (WinRM), with automatic fallback to DCOM (RPC/WMI).
3. **Telemetry Extraction**:
   - Hostname, Domain membership, Manufacturer, Model, Domain role.
   - OS Caption, Version, Build number, Last Boot Time, Uptime days.
   - Hardware: CPU model, Cores, Sockets, Physical Memory Total/Free, Utilization %.
   - Storage: Volume drives, Labels, Filesystem, Size GB, Free Space GB, Free %.
   - Network: IP configurations, Gateways, DNS Server order, DHCP status.
   - Windows Services: Total services, Running count, Stopped automatic services.
   - Security: Firewall profiles, Antivirus / EDR status.
4. **Persistence**: Saves sanitized telemetry to `discovery/windows/remote_<TargetIP>_telemetry.json`.
5. **Compilation**: Ingests into `scripts/compile_assessment.py` to populate all 18 worksheets of `reports/Enterprise_Infrastructure_Health_Check.xlsx`.

---

## 3. Active Directory & VMware Targets

- For **Active Directory / Domain Controllers**:
  Executes DCDiag, FSMO check, SYSVOL/Netlogon replication tests, DNS zone integrity, and stale account queries:
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "scripts/collectors/Invoke-ADHealthDiscovery.ps1" -TargetIP "<IP>" -Username "<User>" -Password "<Password>"
  ```
- For **Hyper-V Cluster / Host Infrastructure**:
  Collects cluster quorum, CSV volumes, Live Migration networks, and VM workloads:
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "scripts/collectors/Invoke-HyperVClusterDiscovery.ps1" -ClusterNode "<IP>" -Username "<User>" -Password "<Password>"
  ```
- For **VMware vCenter / ESXi**:
  Connects via PowerCLI or Python pyVmomi to assess cluster HA/DRS, host CPU ready %, memory ballooning, datastore latency, and snapshots older than 72 hours:
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "scripts/collectors/Invoke-VMwareDiscovery.ps1" -Server "<IP>" -Username "<User>" -Password "<Password>"
  ```

---

## 4. Required Output Deliverables

At the conclusion of the health check:
1. **Root Cause Analysis (RCA)** for each detected issue using the standard schema:
   - Issue ID, Component, Hostname, Environment, Detection, Evidence, Observed condition, Probable root cause, Confidence, Impact, Severity, Recommended remediation, Risk, Rollback plan, Approval required.
2. **Infrastructure Health Check Scorecard**:
   - Overall Infrastructure Status (HEALTHY, WARNING, DEGRADED, CRITICAL)
   - Critical, High, Medium, Low Issue counts
   - Healthy Components & Components Requiring Attention
   - Top Risks & Recommended Next Actions
   - Remediations Waiting for Approval
3. **18-Worksheet Excel Report** generated at:
   `reports/Enterprise_Infrastructure_Health_Check.xlsx`
