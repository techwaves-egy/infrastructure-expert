# Enterprise Infrastructure Operations & Health-Check Framework
**Branding & CoE:** Techwaves EGY Infrastructure Operations & Center of Excellence  
**Role:** Senior Infrastructure Operations & Health-Check Specialist  
**Standard Operating Procedure:** Read-Only Discovery → Root Cause Analysis → Structured Excel Reporting → Explicit Approval Gate → Verified Remediation → Audit Trail

---

## 1. Operating Model & Directory Structure

```plaintext
infrastructure-expert/
├── .agents/                    # Universal Agent specification (Antigravity, Claude, Cursor, Windsurf)
│   └── skills/
│       └── infrastructure-health/
│           └── SKILL.md
├── assets/                     # Architecture diagrams and branding assets
├── docs/                       # Operational frameworks, SOPs, and architectural specifications
│   ├── ARCHITECTURE.md
│   └── OPERATIONAL_FRAMEWORK.md
├── playbooks/                  # Hardening and remediation runbooks with mandatory rollbacks
├── scripts/                    # Automation engine (PowerShell & Python)
│   ├── collectors/             # Non-intrusive read-only telemetry collectors
│   ├── audit_logger.py         # Tamper-evident immutable audit trail logger
│   ├── compile_assessment.py   # Multi-host telemetry ingestion and synthesis engine
│   └── generate_health_report.py # 18-worksheet Excel report generator
├── skills/                     # Antigravity skill definitions
│   └── infrastructure-health/
│       └── SKILL.md
├── templates/                  # Schemas for RCA, reports, and playbooks
│   ├── rca_schema.json
│   └── excel_report_schema.json
├── .cursorrules                # Cursor IDE rules
├── .gitignore                  # Strict leak prevention
├── .windsurfrules              # Windsurf IDE rules
├── AGENTS.md                   # Agent system guidelines
├── CLAUDE.md                   # Claude Code guidelines
├── GEMINI.md                   # Gemini / Antigravity guidelines
├── LICENSE                     # Open source license
├── README.md                   # Master repository documentation
└── skills.json                 # Tool registry schema
```

---

## 2. 18-Worksheet Excel Report Specification

Every infrastructure assessment compiles an Excel workbook (`*.xlsx`) containing:
1. **Executive Summary** (KPIs, Overall Posture Score, Severity Distribution, Critical Blockers)
2. **Scorecard & KPI** (Subsystem compliance metrics across compute, storage, directory, hypervisor)
3. **System & OS Baseline** (Hardware, CPU cores/sockets, RAM pressure, uptime, storage geometry)
4. **Active Directory DS** (Forest/domain functional levels, Recycle Bin, site subnets)
5. **Domain Controllers & FSMO** (DC inventory, role placement, Global Catalog, PDC emulator)
6. **AD Replication & SYSVOL** (Intersite topology, DFSR backlog, SYSVOL/Netlogon shares)
7. **DNS Server & Zones** (Forward/reverse lookups, forwarders, aging & scavenging)
8. **DHCP Server & Scopes** (Scope exhaustion, failover partner sync, lease statistics)
9. **Failover Clustering** (Cluster quorum, witness disk, node health, network routing)
10. **Hyper-V Infrastructure** (Virtual switch geometry, CSV block cache, NUMA, power plans)
11. **Hyper-V Virtual Machines** (VM state, vCPU overcommit, dynamic RAM, snapshots, ISO locks)
12. **VMware vCenter Health** (VCSA appliance health, build level, certificate lifecycle)
13. **VMware ESXi Hosts** (Host readiness %, ballooning, DRS/HA events, memory pressure)
14. **Enterprise Storage & LUNs** (CSV volumes, VMFS datastores, IOPS latency, free space %)
15. **Backup & DR Posture** (Backup agent heartbeat, SLA window, snapshot age > 72h)
16. **Security & CIS Hardening** (Print Spooler, LDAP signing, Channel Binding, Protected Users)
17. **Root Cause Analysis (RCA)** (Formal RCA items with Probable Cause, Impact, and Risk)
18. **Remediation Action Plan** (Prioritized runbooks, rollbacks, and explicit approval tracking)

---

## 3. Strict Safety & Governance Protocol
- **Read-Only Discovery**: Zero state mutations permitted during assessment phases.
- **Explicit Approval Model**: Every change requires unambiguous operator approval referencing specific Issue IDs.
- **Rollback Assurance**: Every remediation playbook must include an automated, tested rollback procedure.
- **Evidence Preservation**: System state and relevant event logs/configurations are captured prior to modification.
