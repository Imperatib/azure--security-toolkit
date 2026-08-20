<#
.SYNOPSIS
    Audits Azure Storage Accounts against CIS Azure Benchmark v2.0
    section 3.x controls: public blob access, HTTPS enforcement,
    minimum TLS version, and network ACL restrictions.

.DESCRIPTION
    Read-only audit script. Requires the Az.Storage and Az.Accounts
    modules and Reader access on the subscription(s) being audited.

.PARAMETER SubscriptionId
    Subscription to audit. Uses current context if omitted.

.PARAMETER OutputPath
    Folder to write the CSV findings to. Defaults to .\reports\

.EXAMPLE
    .\Audit-StorageAccounts.ps1 -SubscriptionId "xxxx-xxxx" -OutputPath .\reports\
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$OutputPath = ".\reports\"
)

if (-not (Get-Module -ListAvailable -Name Az.Storage)) {
    Write-Warning "Az.Storage module not found. Install with: Install-Module Az -Scope CurrentUser"
    return
}

if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$findings = @()

$accounts = Get-AzStorageAccount
Write-Host "Auditing $($accounts.Count) storage account(s)..." -ForegroundColor Cyan

foreach ($acct in $accounts) {
    $name = $acct.StorageAccountName
    $rg   = $acct.ResourceGroupName

    # CIS 3.1 — Secure transfer (HTTPS) should be enabled
    if (-not $acct.EnableHttpsTrafficOnly) {
        $findings += [PSCustomObject]@{
            Account  = $name
            Category = "Secure Transfer"
            Severity = "High"
            Finding  = "HTTPS-only traffic is NOT enforced (CIS 3.1)"
        }
    }

    # CIS 3.2 — storage account public network access
    if ($acct.PublicNetworkAccess -eq "Enabled" -and (-not $acct.NetworkRuleSet -or $acct.NetworkRuleSet.DefaultAction -eq "Allow")) {
        $findings += [PSCustomObject]@{
            Account  = $name
            Category = "Network Access"
            Severity = "High"
            Finding  = "Public network access enabled with default-allow network rules (CIS 3.7)"
        }
    }

    # CIS 3.5 — Minimum TLS version
    if ($acct.MinimumTlsVersion -ne "TLS1_2") {
        $findings += [PSCustomObject]@{
            Account  = $name
            Category = "TLS Version"
            Severity = "Medium"
            Finding  = "Minimum TLS version is $($acct.MinimumTlsVersion), expected TLS1_2 (CIS 3.5)"
        }
    }

    # CIS 3.6 — Blob public access
    if ($acct.AllowBlobPublicAccess) {
        $findings += [PSCustomObject]@{
            Account  = $name
            Category = "Blob Public Access"
            Severity = "Critical"
            Finding  = "Storage account allows public blob access (CIS 3.6)"
        }
    }

    # Resource group tag, for report readability
    foreach ($f in $findings | Where-Object { $_.Account -eq $name }) {
        $f | Add-Member -NotePropertyName ResourceGroup -NotePropertyValue $rg -Force
    }
}

$reportFile = Join-Path $OutputPath "storage_account_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$findings | Export-Csv -Path $reportFile -NoTypeInformation

Write-Host "`nAudit complete: $($findings.Count) findings across $($accounts.Count) account(s) written to $reportFile" -ForegroundColor Green
$findings | Group-Object Severity | Select-Object Name, Count | Format-Table -AutoSize
