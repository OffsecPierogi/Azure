#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Extracts all members of the Global Administrator role in Microsoft Entra ID.

.NOTES
    Uses az rest with Cloud Shell's existing login — no Connect-MgGraph needed.
    Run in Azure Cloud Shell (PowerShell).
#>

function info    ($m) { Write-Host "  [INFO]  $m" -ForegroundColor Cyan   }
function ok      ($m) { Write-Host "  [OK]    $m" -ForegroundColor Green  }
function warn    ($m) { Write-Host "  [WARN]  $m" -ForegroundColor Yellow }
function section ($m) { Write-Host "`n$m"          -ForegroundColor Magenta }

# Global Administrator role template ID — same in every tenant
$GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# ── Login check ────────────────────────────────────────────────────────────────
if (-not (az account show 2>$null)) {
    info "No active session — running az login..."
    az login | Out-Null
}

$tenantId   = az account show --query tenantId   --output tsv
$tenantName = az rest --method GET `
    --url "https://graph.microsoft.com/v1.0/organization" `
    --query "value[0].displayName" --output tsv 2>$null

info "Tenant : $tenantName  ($tenantId)"

# ── Find the activated Global Administrator role ───────────────────────────────
info "Looking up Global Administrator role..."

$roleId = az rest --method GET `
    --url "https://graph.microsoft.com/v1.0/directoryRoles" `
    --query "value[?roleTemplateId=='$GLOBAL_ADMIN_TEMPLATE_ID'].id | [0]" `
    --output tsv 2>$null

# Activate if not yet enabled in this directory
if (-not $roleId -or $roleId -eq "None") {
    info "Role not yet activated — activating via template..."
    az rest --method POST `
        --url "https://graph.microsoft.com/v1.0/directoryRoles" `
        --body "{`"roleTemplateId`": `"$GLOBAL_ADMIN_TEMPLATE_ID`"}" `
        --headers "Content-Type=application/json" 2>$null | Out-Null

    $roleId = az rest --method GET `
        --url "https://graph.microsoft.com/v1.0/directoryRoles" `
        --query "value[?roleTemplateId=='$GLOBAL_ADMIN_TEMPLATE_ID'].id | [0]" `
        --output tsv 2>$null
}

if (-not $roleId -or $roleId -eq "None") {
    Write-Host "  [ERROR] Could not retrieve Global Administrator role. Check your permissions." -ForegroundColor Red
    exit 1
}

ok "Found role  |  Role ID: $roleId"

# ── Get all members ────────────────────────────────────────────────────────────
info "Fetching role members..."

$membersJson = az rest --method GET `
    --url "https://graph.microsoft.com/v1.0/directoryRoles/$roleId/members" `
    --output json 2>$null

$members = ($membersJson | ConvertFrom-Json).value

if (-not $members -or $members.Count -eq 0) {
    warn "No members found in the Global Administrator role."
    exit 0
}

# ── Print results ──────────────────────────────────────────────────────────────
section "════════════════════════════════════════════════════"
Write-Host "  GLOBAL ADMINISTRATOR MEMBERS" -ForegroundColor Magenta
section "════════════════════════════════════════════════════"

$csvRows = [System.Collections.Generic.List[PSCustomObject]]::new()
$counter = 1

foreach ($m in $members) {
    $objType     = $m.'@odata.type' -replace "#microsoft.graph.", ""
    $displayName = if ($m.displayName)        { $m.displayName }        else { "N/A" }
    $upn         = if ($m.userPrincipalName)  { $m.userPrincipalName }  else { "N/A" }
    $enabled     = if ($null -ne $m.accountEnabled) { $m.accountEnabled.ToString() } else { "N/A" }

    Write-Host ("  {0,3}. {1,-40} {2,-50} Type: {3,-20} Enabled: {4}" -f `
        $counter, $displayName, $upn, $objType, $enabled)

    $csvRows.Add([PSCustomObject]@{
        "No."             = $counter
        "Display Name"    = $displayName
        "UPN / App ID"    = $upn
        "Object Type"     = $objType
        "Account Enabled" = $enabled
        "Object ID"       = $m.id
    })
    $counter++
}

# ── Summary ────────────────────────────────────────────────────────────────────
section "════════════════════════════════════════════════════"
Write-Host "  Total Global Administrators : $($members.Count)" -ForegroundColor Green
section "════════════════════════════════════════════════════"

$csvPath = "./GlobalAdmins_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
ok "Results saved to: $csvPath"
