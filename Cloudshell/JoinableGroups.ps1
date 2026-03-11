# =============================================================================
# Find Azure AD / Entra ID Groups Joinable by Users
# Outputs results to CSV, then prompts to join selected groups
# Run from Azure Cloud Shell (PowerShell)
# =============================================================================

$OutputFile = "$HOME/joinable-groups-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$Graph = "https://graph.microsoft.com/v1.0"

Write-Host "============================================="
Write-Host " Scanning for User-Joinable Groups"
Write-Host "============================================="
Write-Host ""

# Acquire token
try {
    $TokenRaw = az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv
    if ([string]::IsNullOrWhiteSpace($TokenRaw)) { throw "Empty token" }
    $Token = $TokenRaw.Trim()
} catch {
    Write-Host "ERROR: Could not acquire access token. Run: az login" -ForegroundColor Red
    exit 1
}

$Headers = @{
    "Authorization"    = "Bearer $Token"
    "Content-Type"     = "application/json"
    "ConsistencyLevel" = "eventual"
}

# Get current user ID
try {
    $Me = Invoke-RestMethod -Uri "$Graph/me?`$select=id" -Headers $Headers -Method Get
    $MyId = $Me.id
    if ([string]::IsNullOrWhiteSpace($MyId)) { throw "No ID" }
} catch {
    Write-Host "ERROR: Could not retrieve your user ID." -ForegroundColor Red
    exit 1
}
Write-Host "Logged in as user ID: $MyId"
Write-Host ""

# Store results
$CsvRows = [System.Collections.Generic.List[PSCustomObject]]::new()
$GroupList = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "Fetching groups..."
Write-Host ""

$NextLink = "$Graph/groups?`$select=id,displayName,description,groupTypes,visibility,mailEnabled,securityEnabled&`$top=999"
$Count = 0

while ($NextLink) {
    try {
        $Response = Invoke-RestMethod -Uri $NextLink -Headers $Headers -Method Get
    } catch {
        Write-Host "ERROR fetching groups: $($_.Exception.Message)" -ForegroundColor Red
        break
    }

    foreach ($Group in $Response.value) {
        $GroupTypes = $Group.groupTypes
        if (-not $GroupTypes) { $GroupTypes = @() }

        # Skip dynamic membership groups
        if ($GroupTypes -contains "DynamicMembership") { continue }

        # Only include Public visibility
        $Visibility = if ($Group.visibility) { $Group.visibility } else { "Unknown" }
        if ($Visibility -ne "Public") { continue }

        $GId = $Group.id
        $DName = if ($Group.displayName) { $Group.displayName } else { "N/A" }
        $Desc = if ($Group.description) { $Group.description -replace "`r|`n", " " } else { "" }
        $Sec = [string]$Group.securityEnabled
        $Mail = [string]$Group.mailEnabled
        $IsUnified = $GroupTypes -contains "Unified"

        # Determine group type label
        if ($IsUnified) {
            $GType = "Microsoft 365"
        } elseif ($Group.securityEnabled -eq $true -and $Group.mailEnabled -eq $true) {
            $GType = "Mail-enabled Security"
        } elseif ($Group.securityEnabled -eq $true) {
            $GType = "Security"
        } else {
            $GType = "Distribution"
        }

        Write-Host "  Processing: $DName"

        # --- Member count ---
        $MCount = "0"
        try {
            $CountHeaders = @{
                "Authorization"    = "Bearer $Token"
                "ConsistencyLevel" = "eventual"
            }
            $MCountRaw = Invoke-RestMethod -Uri "$Graph/groups/$GId/members/`$count" -Headers $CountHeaders -Method Get
            if ($MCountRaw -match '^\d+$') { $MCount = $MCountRaw }
        } catch { }

        # --- Assigned directory roles ---
        $Roles = "None"
        try {
            $RolesResponse = Invoke-RestMethod -Uri "$Graph/groups/$GId/transitiveMemberOf/microsoft.graph.directoryRole?`$select=displayName" -Headers $Headers -Method Get
            if ($RolesResponse.value -and $RolesResponse.value.Count -gt 0) {
                $RoleNames = $RolesResponse.value | ForEach-Object { $_.displayName } | Where-Object { $_ }
                if ($RoleNames) { $Roles = $RoleNames -join "; " }
            }
        } catch { }

        # Store CSV row
        $CsvRows.Add([PSCustomObject]@{
            Id              = $GId
            DisplayName     = $DName
            Description     = $Desc
            SecurityEnabled = $Sec
            MailEnabled     = $Mail
            GroupType       = $GType
            MemberCount     = $MCount
            AssignedRoles   = $Roles
        })

        # Store for join menu
        $GroupList.Add([PSCustomObject]@{
            Id   = $GId
            Name = $DName
        })

        $Count++
    }

    # Pagination
    $NextLink = $Response.'@odata.nextLink'
}

# Export CSV
$CsvRows | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "============================================="
Write-Host " Scan Complete"
Write-Host "============================================="
Write-Host "  Joinable groups found: $Count"
Write-Host "  CSV exported to: $OutputFile"
Write-Host "============================================="
Write-Host ""

# =============================================================================
# Interactive: Join groups
# =============================================================================

if ($Count -eq 0) {
    Write-Host "No joinable groups to display."
    exit 0
}

Write-Host "============================================="
Write-Host " Available Groups to Join"
Write-Host "============================================="
Write-Host ""
for ($j = 0; $j -lt $Count; $j++) {
    Write-Host "  $($j + 1)) $($GroupList[$j].Name)"
}
Write-Host ""
Write-Host "  0) Skip - do not join any groups"
Write-Host ""

while ($true) {
    $Selection = Read-Host "Enter group numbers to join (comma-separated, e.g. 1,3 or 0 to skip)"

    if ($Selection.Trim() -eq "0") {
        Write-Host "Skipping. No groups joined."
        break
    }

    $Picks = $Selection -split ',' | ForEach-Object { $_.Trim() }
    $Valid = $true

    foreach ($Pick in $Picks) {
        if ($Pick -notmatch '^\d+$' -or [int]$Pick -lt 1 -or [int]$Pick -gt $Count) {
            Write-Host "  Invalid selection: $Pick (must be 1-$Count)" -ForegroundColor Yellow
            $Valid = $false
            break
        }
    }

    if (-not $Valid) { continue }

    Write-Host ""
    foreach ($Pick in $Picks) {
        $Idx = [int]$Pick - 1
        $JoinGId = $GroupList[$Idx].Id
        $JoinName = $GroupList[$Idx].Name

        Write-Host -NoNewline "  Joining '$JoinName'... "

        $JoinBody = @{
            "@odata.id" = "$Graph/directoryObjects/$MyId"
        } | ConvertTo-Json

        try {
            Invoke-RestMethod -Uri "$Graph/groups/$JoinGId/members/`$ref" `
                -Headers $Headers -Method Post -Body $JoinBody -ErrorAction Stop
            Write-Host "SUCCESS" -ForegroundColor Green
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 400) {
                Write-Host "ALREADY A MEMBER" -ForegroundColor Yellow
            } else {
                Write-Host "FAILED (HTTP $StatusCode)" -ForegroundColor Red
            }
        }
    }

    Write-Host ""
    Write-Host "Done."
    break
}
