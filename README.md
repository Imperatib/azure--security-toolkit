# Azure Security Hardening Toolkit

**Author:** Brandon Imperati | AZ-500 Candidate | CySA+ | SSCP
**Tools:** PowerShell · Microsoft Graph · Az PowerShell Modules
**Focus:** AZ-500 Exam Alignment · CIS Azure Benchmark v2.0

---

## Overview

A PowerShell-based toolkit for auditing Azure environments against the CIS Microsoft Azure Foundations Benchmark v2.0. Built to operationalize the security principles covered in the AZ-500 certification — bridging certification study with executable, read-only audit scripts across identity, storage, networking, and Defender for Cloud.

All scripts are **read-only** — they audit and report, they do not remediate.

---

## What's Here

```
azure--security-toolkit/
├── identity-access/
│   └── Audit-EntraIDConfig.ps1         # MFA coverage, privileged roles, stale guest accounts
├── data-storage/
│   └── Audit-StorageAccounts.ps1       # HTTPS enforcement, public access, TLS version
├── defender-monitoring/
│   └── Export-DefenderSecureScore.ps1  # Secure Score + unresolved recommendations export
├── network-security/                   # NSG / network exposure audit scripts
└── README.md
```

---

## CIS Azure Benchmark Coverage

| CIS Control | Category            | Status | Script |
| ----------- | -------------------- | ------ | ------ |
| 1.x         | Identity & Access     | ✅ Covered | `identity-access/Audit-EntraIDConfig.ps1` |
| 2.x         | Microsoft Defender     | ✅ Covered | `defender-monitoring/Export-DefenderSecureScore.ps1` |
| 3.x         | Storage Accounts       | ✅ Covered | `data-storage/Audit-StorageAccounts.ps1` |
| 6.x         | Networking             | ✅ Covered | `network-security/` |
| 4.x         | Database Services      | 🔜 Planned |

---

## Requirements

```powershell
Install-Module Az -Scope CurrentUser
Install-Module Microsoft.Graph -Scope CurrentUser
```

Each script requires read-only roles: **Reader** (or Security Reader for Defender) on the target subscription, and for the Entra ID script, Graph permissions `User.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `UserAuthenticationMethod.Read.All`.

## Usage

```powershell
# Identity audit
.\identity-access\Audit-EntraIDConfig.ps1 -OutputPath .\reports\

# Storage account audit
.\data-storage\Audit-StorageAccounts.ps1 -SubscriptionId "<sub-id>" -OutputPath .\reports\

# Defender for Cloud secure score export
.\defender-monitoring\Export-DefenderSecureScore.ps1 -OutputPath .\reports\
```

Each script writes timestamped CSV findings to the output folder for tracking over time.

---

## Roadmap

- [ ] Database services module (CIS 4.x)
- [ ] One-shot `baseline/` runner that executes all modules and produces a combined report
- [ ] Setup guide and AZ-500 domain alignment doc

