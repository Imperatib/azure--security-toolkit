<#
.SYNOPSIS
    Audit-NSGRules.ps1 — Azure Network Security Group Hardening Audit
.DESCRIPTION
    Scans all NSGs across one or more Azure subscriptions and identifies
    overly permissive inbound rules. Flags rules that expose management
    ports or allow unrestricted internet access. Exports a prioritized
    remediation report.
.PARAMETER SubscriptionId
    Target subscription ID. If omitted, scans all accessible subscriptions.
.PARAMETER OutputPath
    Directory for CSV/HTML report output. Defaults to .\reports\
.PARAMETER Severity
    Minimum severity to include: Critical, High, Medium, Low (default: Medium)
.EXAMPLE
    .\Audit-NSGRules.ps1 -SubscriptionId "xxxx-xxxx" -OutputPath ".\reports\"
.NOTES
    Author:      [Your Name]
    Cert Align:  AZ-500 | CIS Azure Benchmark v2.0 Section 6
    MITRE:       T1133 (External Remote Services), T1046 (Network Service Discovery)
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$OutputPath = ".\reports\",
    [ValidateSet("Critical","High","Medium","Low")]
    [string]$Severity = "Medium"
)

#Requires -Modules Az.Network, Az.Accounts

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ─────────────────────────────────────────────────────────────────
$DANGEROUS_PORTS = @{
    22   = @{ Name = "SSH";    Severity = "Critical" }
    3389 = @{ Name = "RDP";    Severity = "Critical" }
    5985 = @{ Name = "WinRM";  Severity = "High"     }
    5986 = @{ Name = "WinRMS"; Severity = "High"     }
    1433 = @{ Name = "MSSQL";  Severity = "High"     }
    3306 = @{ Name = "MySQL";  Severity = "High"     }
    23   = @{ Name = "Telnet"; Severity = "Critical" }
    445  = @{ Name = "SMB";    Severity = "Critical" }
    135  = @{ Name = "RPC";    Severity = "High"     }
}

$SEVERITY_ORDER = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
$findings = [System.Collections.Generic.List[PSObject]]::new()

# ── Helper: Write colored output ──────────────────────────────────────────────
function Write-Finding {
    param([string]$Sev, [string]$Message)
    $color = switch ($Sev) {
        "Critical" { "Red"     }
        "High"     { "Yellow"  }
        "Medium"   { "Cyan"    }
        default    { "White"   }
    }
    Write-Host "  [$Sev] $Message" -ForegroundColor $color
}

# ── Helper: Check if source allows any IP ────────────────────────────────────
function Test-IsAnySource {
    param([string]$AddressPrefix)
    return ($AddressPrefix -eq "*" -or $AddressPrefix -eq "0.0.0.0/0" -or
            $AddressPrefix -eq "Internet" -or $AddressPrefix -eq "Any")
}

# ── Helper: Check port overlap ───────────────────────────────────────────────
function Get-MatchedPorts {
    param([string]$DestPort, [hashtable]$DangerPorts)
    $matched = @()
    if ($DestPort -eq "*") {
        $matched = $DangerPorts.Keys
    } else {
        $portList = $DestPort -split ","
        foreach ($p in $portList) {
            if ($p -match "^(\d+)-(\d+)$") {
                $range = $Matches[1]..$Matches[2]
                $matched += $DangerPorts.Keys | Where-Object { $_ -in $range }
            } elseif ([int]$p -in $DangerPorts.Keys) {
                $matched += [int]$p
            }
        }
    }
    return $matched
}

# ── Core Audit Function ───────────────────────────────────────────────────────
function Invoke-NSGAudit {
    param([string]$SubId)

    Write-Host "`n[*] Auditing NSGs in subscription: $SubId" -ForegroundColor Cyan
    Set-AzContext -SubscriptionId $SubId | Out-Null

    $nsgs = Get-AzNetworkSecurityGroup
    Write-Host "    Found $($nsgs.Count) NSG(s)"

    foreach ($nsg in $nsgs) {
        Write-Host "`n  NSG: $($nsg.Name) [$($nsg.ResourceGroupName)]"

        $inboundRules = $nsg.SecurityRules | Where-Object {
            $_.Direction -eq "Inbound" -and $_.Access -eq "Allow"
        }

        foreach ($rule in $inboundRules) {
            $isAnySource = Test-IsAnySource -AddressPrefix $rule.SourceAddressPrefix

            # Finding 1: Completely open inbound rule
            if ($isAnySource -and $rule.DestinationPortRange -eq "*") {
                $finding = [PSCustomObject]@{
                    Severity        = "Critical"
                    NSG             = $nsg.Name
                    ResourceGroup   = $nsg.ResourceGroupName
                    RuleName        = $rule.Name
                    Priority        = $rule.Priority
                    SourceAddress   = $rule.SourceAddressPrefix
                    DestinationPort = $rule.DestinationPortRange
                    Issue           = "Rule allows ALL inbound traffic from ANY source"
                    CIS_Control     = "6.x"
                    Remediation     = "Remove or scope this rule immediately. Apply principle of least privilege."
                }
                $findings.Add($finding)
                Write-Finding -Sev "Critical" -Message "Rule '$($rule.Name)': ANY source → ANY port (fully open)"
                continue
            }

            # Finding 2: Dangerous management port exposed to internet
            if ($isAnySource) {
                $matchedPorts = Get-MatchedPorts -DestPort $rule.DestinationPortRange -DangerPorts $DANGEROUS_PORTS
                foreach ($port in $matchedPorts) {
                    $portInfo = $DANGEROUS_PORTS[$port]
                    $finding = [PSCustomObject]@{
                        Severity        = $portInfo.Severity
                        NSG             = $nsg.Name
                        ResourceGroup   = $nsg.ResourceGroupName
                        RuleName        = $rule.Name
                        Priority        = $rule.Priority
                        SourceAddress   = $rule.SourceAddressPrefix
                        DestinationPort = $port
                        Issue           = "Management port $port ($($portInfo.Name)) exposed to internet"
                        CIS_Control     = "6.x"
                        Remediation     = "Restrict source to known IPs or use Azure Bastion / VPN gateway"
                    }
                    $findings.Add($finding)
                    Write-Finding -Sev $portInfo.Severity -Message "Port $port ($($portInfo.Name)) open to ANY source"
                }
            }

            # Finding 3: Rules without description (governance gap)
            if ([string]::IsNullOrEmpty($rule.Description)) {
                $finding = [PSCustomObject]@{
                    Severity        = "Low"
                    NSG             = $nsg.Name
                    ResourceGroup   = $nsg.ResourceGroupName
                    RuleName        = $rule.Name
                    Priority        = $rule.Priority
                    SourceAddress   = $rule.SourceAddressPrefix
                    DestinationPort = $rule.DestinationPortRange
                    Issue           = "Rule has no description — ownership unknown"
                    CIS_Control     = "Governance"
                    Remediation     = "Add description with owner, purpose, and change ticket reference"
                }
                $findings.Add($finding)
            }
        }
    }
}

# ── Main ──────────────────────────────────────────────────────────────────────
function Main {
    Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host   "║   Azure NSG Security Audit  |  [Your Name]      ║" -ForegroundColor Cyan
    Write-Host   "╚══════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    # Ensure connected
    try { Get-AzContext -ErrorAction Stop | Out-Null }
    catch { Connect-AzAccount }

    if ($SubscriptionId) {
        Invoke-NSGAudit -SubId $SubscriptionId
    } else {
        $subs = Get-AzSubscription
        Write-Host "[*] No subscription specified. Scanning $($subs.Count) subscription(s)."
        foreach ($sub in $subs) { Invoke-NSGAudit -SubId $sub.Id }
    }

    # Filter by minimum severity
    $filtered = $findings | Where-Object { $SEVERITY_ORDER[$_.Severity] -ge $SEVERITY_ORDER[$Severity] }
    $sorted   = $filtered | Sort-Object { $SEVERITY_ORDER[$_.Severity] } -Descending

    Write-Host "`n╔══════════════════════════════════╗" -ForegroundColor White
    Write-Host   "║         AUDIT SUMMARY            ║" -ForegroundColor White
    Write-Host   "╚══════════════════════════════════╝"
    Write-Host "  Total findings : $($sorted.Count)"
    Write-Host "  Critical       : $(($sorted | Where-Object Severity -eq 'Critical').Count)" -ForegroundColor Red
    Write-Host "  High           : $(($sorted | Where-Object Severity -eq 'High').Count)"     -ForegroundColor Yellow
    Write-Host "  Medium         : $(($sorted | Where-Object Severity -eq 'Medium').Count)"   -ForegroundColor Cyan
    Write-Host "  Low            : $(($sorted | Where-Object Severity -eq 'Low').Count)"

    # Export
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $timestamp  = Get-Date -Format "yyyyMMdd_HHmm"
    $csvPath    = Join-Path $OutputPath "nsg_audit_$timestamp.csv"
    $sorted | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`n[✓] Report exported: $csvPath" -ForegroundColor Green
}

Main
