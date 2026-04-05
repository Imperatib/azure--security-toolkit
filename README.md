# Azure Security Hardening Toolkit

**Author:** Brandon Imperati | AZ-500 Candidate | CySA+ | SSCP  
**Tools:** PowerShell · Azure CLI · Microsoft Defender for Cloud · Entra ID  
**Focus:** AZ-500 Exam Alignment · CIS Azure Benchmark · Zero Trust Architecture

---

## Overview

A PowerShell-based toolkit for auditing and hardening Azure environments against the CIS Microsoft Azure Foundations Benchmark v2.0 and Microsoft's Zero Trust security model. Each script targets specific AZ-500 exam domains and real-world misconfiguration patterns commonly found during cloud security assessments.

Built to operationalize the security principles covered in the AZ-500 certification — bridging certification knowledge with executable security controls.

---

## Repository Structure

```
azure-security-toolkit/
├── identity-access/
│   ├── Audit-EntraIDConfig.ps1          # MFA, Conditional Access, PIM audit
│   ├── Review-PrivilegedRoles.ps1       # Over-privileged role assignments
│   └── Export-GuestAccounts.ps1        # Stale/risky guest user report
├── network-security/
│   ├── Audit-NSGRules.ps1              # Open port / permissive rule detection
│   ├── Assess-PublicExposure.ps1       # Public IP & exposed resource inventory
│   └── Check-DDoSProtection.ps1       # DDoS Standard plan coverage audit
├── data-storage/
│   ├── Audit-StorageAccounts.ps1       # Public blob, HTTPS, encryption checks
│   ├── Review-KeyVaultAccess.ps1       # Key Vault policy & logging audit
│   └── Check-SQLEncryption.ps1        # TDE, audit logging, threat detection
├── defender-monitoring/
│   ├── Enable-DefenderPlans.ps1        # Enable Defender for Cloud workload plans
│   ├── Export-SecureScoreReport.ps1    # Secure Score trend & recommendation export
│   └── Configure-AlertSuppression.ps1 # Tune alert rules to reduce noise
├── baseline/
│   ├── full_hardening_baseline.ps1     # All-in-one baseline assessment runner
│   └── CIS_Azure_v2_mapping.md        # Script-to-CIS-control mapping table
└── docs/
    ├── setup_guide.md
    └── az500_alignment.md
```

---

## Featured Scripts

### `Audit-EntraIDConfig.ps1` — Identity Hardening Audit
Validates Entra ID (Azure AD) configuration against AZ-500 identity security requirements:
- Confirms MFA registration for all users and enforced for admins
- Reviews Conditional Access policies for coverage gaps
- Identifies inactive privileged accounts (PIM eligible vs active)
- Flags accounts missing SSPR registration
- Exports findings to CSV with risk rating per finding

### `Audit-NSGRules.ps1` — Network Security Group Audit
Scans all NSGs across subscriptions and flags dangerous rules:
- Any rule allowing inbound `0.0.0.0/0` (any source)
- Open management ports: RDP (3389), SSH (22), WinRM (5985/5986)
- Rules without description/owner tags (governance gap)
- Outputs prioritized remediation list

### `full_hardening_baseline.ps1` — One-Shot Baseline Assessment
Runs all audit modules sequentially and produces a consolidated HTML security report with:
- CIS Benchmark control pass/fail status
- Microsoft Secure Score alignment
- Prioritized remediation roadmap (Critical → High → Medium)

---

## CIS Azure Benchmark Coverage

| CIS Control | Category | Script |
|-------------|----------|--------|
| 1.x | Identity & Access | `Audit-EntraIDConfig.ps1` |
| 2.x | Microsoft Defender | `Enable-DefenderPlans.ps1` |
| 3.x | Storage Accounts | `Audit-StorageAccounts.ps1` |
| 4.x | Database Services | `Check-SQLEncryption.ps1` |
| 5.x | Logging & Monitoring | `Export-SecureScoreReport.ps1` |
| 6.x | Networking | `Audit-NSGRules.ps1` |
| 8.x | Virtual Machines | Included in baseline runner |

---

## Quick Start

```powershell
# Prerequisites
Install-Module Az -Scope CurrentUser -Force
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Connect-AzAccount
Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All"

# Run full baseline assessment
cd azure-security-toolkit/baseline
.\full_hardening_baseline.ps1 -SubscriptionId "your-sub-id" -OutputPath ".\reports\"

# Run individual audit
cd identity-access
.\Audit-EntraIDConfig.ps1 -ExportCSV -OutputPath ".\reports\entra_audit.csv"
```

---

## Alignment to AZ-500 Exam Domains

| Exam Domain | Coverage |
|-------------|----------|
| Manage Identity & Access (25–30%) | Entra ID, PIM, Conditional Access scripts |
| Secure Networking (20–25%) | NSG, DDoS, public exposure audits |
| Secure Compute, Storage & DB (20–25%) | Storage, SQL, Key Vault scripts |
| Manage Security Operations (25–30%) | Defender for Cloud, Secure Score, alerting |
