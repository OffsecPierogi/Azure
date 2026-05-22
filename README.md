# Azure Offensive Security Toolkit

A collection of Bash and PowerShell scripts for Azure security assessments, covering IAM privilege escalation, container security, Key Vault exposure, Entra ID configuration, and more. Designed to run in Azure Cloud Shell or any authenticated terminal.

---

## Scripts

### IAM / Identity

| Script | Shell | Description |
|--------|-------|-------------|
| `IAMPrivz.sh` | Bash | Audits all RBAC role definitions and assignments across the tenant for dangerous privilege-escalation permissions: `roleAssignments/write`, `roleDefinitions/write`, and `federatedIdentityCredentials/write`. Resolves principal identities (users, service principals, groups) for each flagged assignment. Outputs JSON and text reports. |
| `EntraUserSettings.sh` | Bash | Reports Entra ID tenant-level user settings via Microsoft Graph — app registration permissions, tenant creation, security group creation, guest access restriction level, and admin center restrictions. |
| `EntraUserSettings.ps1` | PowerShell | PowerShell equivalent of `EntraUserSettings.sh`. |
| `GlobalAdmins.sh` | Bash | Extracts all members of the Global Administrator directory role. Collects display name, UPN, object type, account status, and object ID. Activates the role if not yet activated in the directory. Outputs formatted table + timestamped CSV. |
| `GlobalAdmin.ps1` | PowerShell | PowerShell equivalent of `GlobalAdmins.sh`. |
| `GuestInvite.sh` | Bash | Audits guest invitation policies and external collaboration settings — who can invite guests, guest access restriction tiers, email-based signup permissions. Flags high-risk configurations (e.g., "everyone can invite"). Outputs timestamped report. |
| `GuestInvite.ps1` | PowerShell | PowerShell equivalent of `GuestInvite.sh`. |
| `JoinableGroups.sh` | Bash | Discovers publicly-joinable Entra ID groups (public visibility, non-dynamic membership). Gathers metadata, member counts, and assigned directory roles. Provides an interactive menu to select and join groups. Outputs CSV. |
| `JoinableGroups.ps1` | PowerShell | PowerShell equivalent of `JoinableGroups.sh`. |

### Container Security

| Script | Shell | Description |
|--------|-------|-------------|
| `Conreg.sh` | Bash | Enumerates role assignments across all subscriptions and ACRs, cross-referencing 14 dangerous ACR permissions (admin credential access, token generation, task creation with managed identities, registry config changes). Performs **live capability tests** — actually attempts operations to confirm exploitability, then cleans up test resources. Outputs timestamped report. |
| `ContainerPermz.sh` | Bash | Audits container resources (ACR, Container Apps, Container Instances) across all subscriptions. Enumerates role assignments scoped to container services, identifies principals with write/Owner/Contributor, and checks which Container Apps and Instances have managed identities enabled. Outputs two CSVs. |
| `ContainerPermz.ps1` | PowerShell | PowerShell equivalent of `ContainerPermz.sh`. |

### Key Vault

| Script | Shell | Description |
|--------|-------|-------------|
| `KV-Access.sh` | Bash | Tests whether the current user has actual data-plane access to Key Vaults across selected subscriptions. Attempts to list secrets, keys, and certificates in each vault. Supports interactive, specific (`-s`), or all (`-a`) subscription selection. Outputs timestamped report. |
| `KV-Access.ps1` | PowerShell | PowerShell equivalent of `KV-Access.sh`. Uses `-SubscriptionIds` and `-All` flags. |
| `KV-PublicAccess.sh` | Bash | Audits network configuration of every Key Vault across all subscriptions. Classifies each vault as Publicly Accessible, Firewall Restricted, Private Only, or Limited. Checks public network access, default ACL action, IP/VNet rules, and private endpoints. Outputs CSV. |
| `KV-PublicAccess.ps1` | PowerShell | PowerShell equivalent of `KV-PublicAccess.sh`. |

### Automation

| Script | Shell | Description |
|--------|-------|-------------|
| `RunbookGrabz.sh` | Bash | Comprehensive audit of all Azure Automation Accounts across all subscriptions. Extracts runbook source code, webhook configurations, schedules, job history (past 30 days), and hybrid worker details. Outputs hierarchical directory structure with per-account detail files and dedicated runbook content folders. |
| `RunbookGrabz.ps1` | PowerShell | PowerShell equivalent of `RunbookGrabz.sh`. |

### SQL

| Script | Shell | Description |
|--------|-------|-------------|
| `SQLAuditing.sh` | Bash | Checks auditing status for all Azure SQL Servers and Databases across all subscriptions. Checks blob, Log Analytics, and Event Hub targets. Smart logic: skips database-level checks when server-level auditing is already enabled. Flags uncovered databases. Outputs CSV. |
| `SQLAuditing.ps1` | PowerShell | PowerShell equivalent of `SQLAuditing.sh`. |

---

## Prerequisites

- **Azure CLI** (`az login`) or **Azure Cloud Shell** session
- **`jq`** — required for all Bash scripts
- **Az PowerShell modules** — required for `.ps1` scripts (`Az.Accounts`, `Az.KeyVault`, `Az.Sql`, etc.)
- Appropriate read permissions for the resources being audited (Reader at minimum; some scripts like `Conreg.sh` test write operations)

---

## Usage

```bash
# Run from Azure Cloud Shell or any authenticated terminal
az login

# IAM privilege escalation audit
bash Cloudshell/IAMPrivz.sh

# Container registry permission check with live tests
bash Cloudshell/Conreg.sh

# Key Vault access test (all subscriptions)
bash Cloudshell/KV-Access.sh -a

# Key Vault public exposure audit
bash Cloudshell/KV-PublicAccess.sh

# PowerShell equivalents
pwsh Cloudshell/KV-Access.ps1 -All
pwsh Cloudshell/ContainerPermz.ps1
```

---

## File Structure

```
Azure/
├── README.md
└── Cloudshell/
    ├── IAMPrivz.sh
    ├── Conreg.sh
    ├── ContainerPermz.sh
    ├── ContainerPermz.ps1
    ├── EntraUserSettings.sh
    ├── EntraUserSettings.ps1
    ├── GlobalAdmins.sh
    ├── GlobalAdmin.ps1
    ├── GuestInvite.sh
    ├── GuestInvite.ps1
    ├── JoinableGroups.sh
    ├── JoinableGroups.ps1
    ├── KV-Access.sh
    ├── KV-Access.ps1
    ├── KV-PublicAccess.sh
    ├── KV-PublicAccess.ps1
    ├── RunbookGrabz.sh
    ├── RunbookGrabz.ps1
    ├── SQLAuditing.sh
    └── SQLAuditing.ps1
```

---

## Disclaimer

These tools are intended for authorized security assessments and educational purposes only. Always obtain proper authorization before running these scripts against any Azure environment.
