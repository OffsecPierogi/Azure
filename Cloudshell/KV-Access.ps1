<#
.SYNOPSIS
    Checks if the current user has access to any Azure Key Vaults

.DESCRIPTION
    This script identifies all Key Vaults in subscriptions and checks
    if the current user has access permissions to them. Results are saved
    to a timestamped text file.

.PARAMETER SubscriptionIds
    Optional. Comma-separated subscription IDs to check (e.g., "sub1,sub2,sub3")
    If not provided, you'll be prompted to select from available subscriptions

.PARAMETER All
    Check all available subscriptions

.EXAMPLE
    .\check-keyvault-access.ps1
    # Interactive mode - prompts for subscription selection

.EXAMPLE
    .\check-keyvault-access.ps1 -SubscriptionIds "xxxxx-xxxx,yyyyy-yyyy"
    # Check specific subscriptions

.EXAMPLE
    .\check-keyvault-access.ps1 -All
    # Check all subscriptions

.NOTES
    Designed for Azure Cloud Shell
    Required Permissions: Reader access to subscriptions and Key Vaults
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionIds,
    
    [Parameter(Mandatory=$false)]
    [switch]$All
)

Write-Host "Azure Key Vault Access Checker" -ForegroundColor Cyan
Write-Host "================================`n" -ForegroundColor Cyan

# Get current user context
Write-Host "Getting current user context..." -ForegroundColor Yellow
$currentUser = az account show --query user.name -o tsv
$tenantId = az account show --query tenantId -o tsv

Write-Host "User: $currentUser" -ForegroundColor Green
Write-Host "Tenant ID: $tenantId`n" -ForegroundColor Green

# Get all available subscriptions
Write-Host "Retrieving available subscriptions..." -ForegroundColor Yellow
$allSubscriptionsJson = az account list --query "[].{id:id, name:name, state:state}" -o json
$allSubscriptions = $allSubscriptionsJson | ConvertFrom-Json | Where-Object { $_.state -eq "Enabled" }

if ($allSubscriptions.Count -eq 0) {
    Write-Host "No enabled subscriptions found." -ForegroundColor Red
    exit 1
}

# Determine which subscriptions to check
$subscriptionsToCheck = @()

if ($All) {
    Write-Host "Checking ALL subscriptions ($($allSubscriptions.Count) total)`n" -ForegroundColor Green
    $subscriptionsToCheck = $allSubscriptions
}
elseif ($SubscriptionIds) {
    $requestedIds = $SubscriptionIds -split ','
    foreach ($id in $requestedIds) {
        $id = $id.Trim()
        $sub = $allSubscriptions | Where-Object { $_.id -eq $id }
        if ($sub) {
            $subscriptionsToCheck += $sub
        }
        else {
            Write-Host "Warning: Subscription ID '$id' not found or not accessible" -ForegroundColor Yellow
        }
    }
    
    if ($subscriptionsToCheck.Count -eq 0) {
        Write-Host "No valid subscriptions found to check." -ForegroundColor Red
        exit 1
    }
}
else {
    # Interactive mode - let user select
    Write-Host "Available Subscriptions:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $allSubscriptions.Count; $i++) {
        Write-Host "  [$($i + 1)] $($allSubscriptions[$i].name) ($($allSubscriptions[$i].id))" -ForegroundColor White
    }
    Write-Host "  [A] All subscriptions" -ForegroundColor White
    
    $selection = Read-Host "`nEnter subscription number(s) separated by commas (e.g., 1,3,5) or 'A' for all"
    
    if ($selection -eq 'A' -or $selection -eq 'a') {
        $subscriptionsToCheck = $allSubscriptions
        Write-Host "Selected: All subscriptions`n" -ForegroundColor Green
    }
    else {
        $indices = $selection -split ',' | ForEach-Object { $_.Trim() }
        foreach ($index in $indices) {
            if ($index -match '^\d+$') {
                $idx = [int]$index - 1
                if ($idx -ge 0 -and $idx -lt $allSubscriptions.Count) {
                    $subscriptionsToCheck += $allSubscriptions[$idx]
                }
                else {
                    Write-Host "Warning: Invalid selection '$index' - skipping" -ForegroundColor Yellow
                }
            }
        }
        
        if ($subscriptionsToCheck.Count -eq 0) {
            Write-Host "No valid subscriptions selected." -ForegroundColor Red
            exit 1
        }
        
        Write-Host "Selected $($subscriptionsToCheck.Count) subscription(s)`n" -ForegroundColor Green
    }
}

Write-Host "Subscriptions to check:" -ForegroundColor Cyan
foreach ($sub in $subscriptionsToCheck) {
    Write-Host "  - $($sub.name) ($($sub.id))" -ForegroundColor Gray
}
Write-Host ""

# Prepare output file
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputFile = "keyvault-access-report-$timestamp.txt"

# Start building output
$output = @()
$output += "========================================"
$output += "AZURE KEY VAULT ACCESS REPORT"
$output += "========================================"
$output += ""
$output += "Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$output += "User: $currentUser"
$output += "Tenant ID: $tenantId"
$output += "Subscriptions Checked: $($subscriptionsToCheck.Count)"
$output += ""

# Track overall accessible vaults
$totalAccessibleVaults = 0
$totalInaccessibleVaults = 0
$totalVaults = 0

# Process each subscription
foreach ($subscription in $subscriptionsToCheck) {
    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host "Subscription: $($subscription.name)" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    
    $output += "========================================"
    $output += "Subscription: $($subscription.name)"
    $output += "Subscription ID: $($subscription.id)"
    $output += "========================================"
    $output += ""
    
    # Set active subscription
    az account set --subscription $subscription.id | Out-Null
    
    # Get all Key Vaults in this subscription
    Write-Host "Scanning for Key Vaults..." -ForegroundColor Yellow
    $vaultsJson = az keyvault list --query "[].{name:name, resourceGroup:resourceGroup, location:location}" -o json 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to list Key Vaults in this subscription" -ForegroundColor Red
        $output += "Error: Failed to list Key Vaults in this subscription"
        $output += ""
        continue
    }
    
    $vaults = $vaultsJson | ConvertFrom-Json
    
    if ($vaults.Count -eq 0) {
        Write-Host "No Key Vaults found in this subscription.`n" -ForegroundColor Yellow
        $output += "No Key Vaults found in this subscription."
        $output += ""
        continue
    }
    
    Write-Host "Found $($vaults.Count) Key Vault(s)`n" -ForegroundColor Green
    $output += "Total Key Vaults Found: $($vaults.Count)"
    $output += ""
    
    $totalVaults += $vaults.Count
    
    # Track accessible vaults in this subscription
    $accessibleVaults = 0
    $inaccessibleVaults = 0
    
    foreach ($vault in $vaults) {
        Write-Host "Checking: $($vault.name)" -ForegroundColor Cyan
        $output += "----------------------------------------"
        $output += "Key Vault: $($vault.name)"
        $output += "Resource Group: $($vault.resourceGroup)"
        $output += "Location: $($vault.location)"
        
        # Try to list secrets to check access
        $secretsResult = az keyvault secret list --vault-name $vault.name 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $secrets = $secretsResult | ConvertFrom-Json
            $secretCount = $secrets.Count
            
            Write-Host "  ✓ ACCESS GRANTED" -ForegroundColor Green
            Write-Host "    - Can list secrets: Yes" -ForegroundColor Gray
            Write-Host "    - Secret count: $secretCount`n" -ForegroundColor Gray
            
            $output += "Access Status: ✓ GRANTED"
            $output += "  - Can list secrets: Yes"
            $output += "  - Secret count: $secretCount"
            
            # Check for specific permissions
            $permissions = @()
            
            # Check if can list keys
            $keysResult = az keyvault key list --vault-name $vault.name 2>&1
            if ($LASTEXITCODE -eq 0) {
                $permissions += "List Keys"
            }
            
            # Check if can list certificates
            $certsResult = az keyvault certificate list --vault-name $vault.name 2>&1
            if ($LASTEXITCODE -eq 0) {
                $permissions += "List Certificates"
            }
            
            if ($permissions.Count -gt 0) {
                $output += "  - Additional Permissions: $($permissions -join ', ')"
            }
            
            $accessibleVaults++
            $totalAccessibleVaults++
        }
        else {
            Write-Host "  ✗ ACCESS DENIED" -ForegroundColor Red
            Write-Host "    - Error: $($secretsResult -split "`n" | Select-Object -First 1)`n" -ForegroundColor Gray
            
            $output += "Access Status: ✗ DENIED"
            $errorMsg = $secretsResult -split "`n" | Select-Object -First 1
            $output += "  - Error: $errorMsg"
            
            $inaccessibleVaults++
            $totalInaccessibleVaults++
        }
        
        $output += ""
    }
    
    # Subscription summary
    Write-Host "Subscription Summary:" -ForegroundColor Yellow
    Write-Host "  Total Key Vaults: $($vaults.Count)" -ForegroundColor White
    Write-Host "  Accessible: $accessibleVaults" -ForegroundColor Green
    Write-Host "  Inaccessible: $inaccessibleVaults" -ForegroundColor Red
    
    $output += "Subscription Summary:"
    $output += "  Total Key Vaults: $($vaults.Count)"
    $output += "  Accessible: $accessibleVaults"
    $output += "  Inaccessible: $inaccessibleVaults"
    $output += ""
}

# Overall Summary
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "OVERALL SUMMARY" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Subscriptions Checked: $($subscriptionsToCheck.Count)" -ForegroundColor White
Write-Host "Total Key Vaults: $totalVaults" -ForegroundColor White
Write-Host "Accessible: $totalAccessibleVaults" -ForegroundColor Green
Write-Host "Inaccessible: $totalInaccessibleVaults" -ForegroundColor Red

$output += "========================================"
$output += "OVERALL SUMMARY"
$output += "========================================"
$output += "Subscriptions Checked: $($subscriptionsToCheck.Count)"
$output += "Total Key Vaults: $totalVaults"
$output += "Accessible: $totalAccessibleVaults"
$output += "Inaccessible: $totalInaccessibleVaults"
$output += ""

if ($totalAccessibleVaults -eq 0) {
    Write-Host "`n⚠️  WARNING: You do not have access to any Key Vaults" -ForegroundColor Yellow
    Write-Host "No output file created (no accessible vaults found)`n" -ForegroundColor Gray
}
else {
    # Write to file only if there are accessible vaults
    $output | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Host "`nReport saved to: $outputFile" -ForegroundColor Green
}
