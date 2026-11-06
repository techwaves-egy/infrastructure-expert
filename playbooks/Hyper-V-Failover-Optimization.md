# Hyper-V & Failover Cluster Optimization Playbook

## 1. Objective & Scope
Optimizes cluster performance and eliminates CSV latency across Hyper-V failover clusters:
- Enable Cluster Shared Volume (CSV) Block Cache
- Configure High Performance OS Power Plan
- Enforce dedicated Live Migration network

---

## 2. CSV Block Cache Configuration
### Detection:
```powershell
(Get-Cluster).BlockCacheSize
```
### Remediation (Allocate 2048 MB cache):
```powershell
(Get-Cluster).BlockCacheSize = 2048
```
### Rollback:
```powershell
(Get-Cluster).BlockCacheSize = 0
```

---

## 3. High Performance Power Plan Enforcement
### Detection:
```powershell
powercfg /getactivescheme
```
### Remediation:
```powershell
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
```
### Rollback (Balanced):
```powershell
powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e
```
