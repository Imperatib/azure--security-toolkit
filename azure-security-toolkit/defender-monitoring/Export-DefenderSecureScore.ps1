<#
.SYNOPSIS
    Exports Microsoft Defender for Cloud Secure Score and unhealthy
    resource recommendations to CSV for tracking and reporting.

.DESCRIPTION
    Read-only audit script. Requires the Az.Security module and
    Security Reader (or higher) on the subscription being audited.

.PARAMETER OutputPath
    Folder to write the CSV findings to. Defaults to .\reports\

.EXAMPLE
    .\Export-DefenderSecureScore.ps1 -OutputPath .\reports\
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\reports\"
)

if (-not (Get-Module -ListAvailable -Name Az.Security)) {
    Write-Warning "Az.Security module not found. Install with: Install-Module Az -Scope CurrentUser"
    return
}

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

Write-Host "Fetching Secure Score..." -ForegroundColor Cyan
$secureScores = Get-AzSecuritySecureScore
$secureScores | Select-Object Name, DisplayName,
    @{N = "CurrentScore"; E = { $_.Score.Current } },
    @{N = "MaxScore"; E = { $_.Score.Max } },
    @{N = "PercentageScore"; E = { if ($_.Score.Max) { [math]::Round(($_.Score.Current / $_.Score.Max) * 100, 1) } else { 0 } } } |
    Export-Csv -Path (Join-Path $OutputPath "secure_score_$(Get-Date -Format 'yyyyMMdd').csv") -NoTypeInformation

Write-Host "Fetching unhealthy resource recommendations..." -ForegroundColor Cyan
$tasks = Get-AzSecurityTask | Where-Object { $_.State -ne "Resolved" }
$tasks | Select-Object Name, State,
    @{N = "Recommendation"; E = { $_.SecurityTaskParameters.Name } },
    @{N = "ResourceId"; E = { $_.Id } } |
    Export-Csv -Path (Join-Path $OutputPath "unresolved_recommendations_$(Get-Date -Format 'yyyyMMdd').csv") -NoTypeInformation

Write-Host "`nExport complete. $($tasks.Count) unresolved recommendation(s) found." -ForegroundColor Green
