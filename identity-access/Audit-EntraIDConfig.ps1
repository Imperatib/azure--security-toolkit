<#
.SYNOPSIS
    Audits Entra ID (Azure AD) configuration against common AZ-500 / CIS
    Azure Benchmark identity controls: MFA coverage, privileged role
    assignments, and stale guest accounts.

.DESCRIPTION
    Read-only audit script. Requires Microsoft.Graph PowerShell module
    and delegated/app permissions: User.Read.All, Directory.Read.All,
    RoleManagement.Read.Directory, UserAuthenticationMethod.Read.All.

.PARAMETER OutputPath
    Folder to write the CSV findings to. Defaults to .\reports\

.EXAMPLE
    .\Audit-EntraIDConfig.ps1 -OutputPath .\reports\
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\reports\"
)

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
    Write-Warning "Microsoft.Graph module not found. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
    return
}

Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Identity.Governance

if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory", "UserAuthenticationMethod.Read.All"
}

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$findings = @()

Write-Host "Checking MFA registration for all users..." -ForegroundColor Cyan
$users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled
foreach ($user in $users) {
    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop
        $hasMfa = $methods | Where-Object { $_.AdditionalProperties["@odata.type"] -notmatch "passwordAuthenticationMethod" }
        if (-not $hasMfa -and $user.AccountEnabled) {
            $findings += [PSCustomObject]@{
                Category    = "MFA"
                Severity    = "High"
                Object      = $user.UserPrincipalName
                Finding     = "No MFA method registered on an enabled account"
            }
        }
    } catch {
        Write-Verbose "Could not read auth methods for $($user.UserPrincipalName): $_"
    }
}

Write-Host "Checking privileged role assignments..." -ForegroundColor Cyan
$privilegedRoles = @("Global Administrator", "Privileged Role Administrator", "Security Administrator")
$roleDefs = Get-MgDirectoryRole -All | Where-Object { $_.DisplayName -in $privilegedRoles }
foreach ($role in $roleDefs) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
    foreach ($member in $members) {
        $findings += [PSCustomObject]@{
            Category = "Privileged Role"
            Severity = "Informational — review for least-privilege"
            Object   = $member.Id
            Finding  = "Assigned to role: $($role.DisplayName)"
        }
    }
}

Write-Host "Checking for stale guest accounts (no sign-in activity in 90+ days)..." -ForegroundColor Cyan
$staleCutoff = (Get-Date).AddDays(-90)
$guests = Get-MgUser -All -Filter "userType eq 'Guest'" -Property Id, DisplayName, UserPrincipalName, SignInActivity
foreach ($guest in $guests) {
    $lastSignIn = $guest.SignInActivity.LastSignInDateTime
    if (-not $lastSignIn -or $lastSignIn -lt $staleCutoff) {
        $findings += [PSCustomObject]@{
            Category = "Guest Account"
            Severity = "Medium"
            Object   = $guest.UserPrincipalName
            Finding  = "No sign-in activity in 90+ days — candidate for removal"
        }
    }
}

$reportFile = Join-Path $OutputPath "entra_id_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$findings | Export-Csv -Path $reportFile -NoTypeInformation

Write-Host "`nAudit complete: $($findings.Count) findings written to $reportFile" -ForegroundColor Green
$findings | Group-Object Category | Select-Object Name, Count | Format-Table -AutoSize
