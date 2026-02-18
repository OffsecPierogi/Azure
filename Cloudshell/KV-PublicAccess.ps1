# Azure Key Vault Network Configuration Audit Script (PowerShell)
# Checks for publicly accessible Key Vaults across all subscriptions

# Output file
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvFile = "keyvault_accessibility_$timestamp.csv"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Azure Key Vault Network Audit" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Az module is available
Write-Host "Checking Azure PowerShell module..." -ForegroundColor Yellow
if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
    Write-Host "Error: Az.KeyVault module is not installed" -ForegroundColor Red
    Write-Host "Please install with: Install-Module -Name Az -AllowClobber -Scope CurrentUser" -ForegroundColor Yellow
    exit 1
}

# Check if logged in
Write-Host "Checking Azure authentication..." -ForegroundColor Yellow
try {
    $context = Get-AzContext
    if (-not $context) {
        throw "Not authenticated"
    }
    Write-Host "✓ Authenticated to Azure" -ForegroundColor Green
    Write-Host "  Account: $($context.Account.Id)" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "Error: Not logged into Azure. Please run 'Connect-AzAccount'" -ForegroundColor Red
    exit 1
}

# Initialize results array
$results = @()

# Get all subscriptions
Write-Host "Fetching subscriptions..." -ForegroundColor Yellow
$subscriptions = Get-AzSubscription

if (-not $subscriptions) {
    Write-Host "No subscriptions found" -ForegroundColor Red
    exit 1
}

$totalSubs = $subscriptions.Count
Write-Host "✓ Found $totalSubs subscription(s)" -ForegroundColor Green
Write-Host ""

$currentSub = 0
$totalKV = 0
$publicKV = 0

# Loop through each subscription
foreach ($sub in $subscriptions) {
    $currentSub++
    $subName = $sub.Name
    $subId = $sub.Id
    
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host "[$currentSub/$totalSubs] Processing: $subName" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    
    # Set subscription context
    try {
        Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "  Failed to set subscription context" -ForegroundColor Red
        continue
    }
    
    # Get all Key Vaults in subscription
    $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
    
    if (-not $keyVaults) {
        Write-Host "  No Key Vaults found in this subscription" -ForegroundColor Yellow
        Write-Host ""
        continue
    }
    
    $kvCount = $keyVaults.Count
    Write-Host "  Found $kvCount Key Vault(s)" -ForegroundColor Green
    Write-Host ""
    
    # Loop through each Key Vault
    foreach ($kv in $keyVaults) {
        $totalKV++
        $kvName = $kv.VaultName
        $rgName = $kv.ResourceGroupName
        $location = $kv.Location
        
        Write-Host "    Checking: $kvName" -ForegroundColor White
        
        # Get detailed network configuration
        try {
            $kvDetails = Get-AzKeyVault -VaultName $kvName -ResourceGroupName $rgName -ErrorAction Stop
            
            # Extract network settings
            $publicAccess = if ($kvDetails.PublicNetworkAccess) { $kvDetails.PublicNetworkAccess } else { "Enabled" }
            $defaultAction = if ($kvDetails.NetworkAcls.DefaultAction) { $kvDetails.NetworkAcls.DefaultAction } else { "Allow" }
            $ipRules = if ($kvDetails.NetworkAcls.IpAddressRanges) { $kvDetails.NetworkAcls.IpAddressRanges.Count } else { 0 }
            $vnetRules = if ($kvDetails.NetworkAcls.VirtualNetworkResourceIds) { $kvDetails.NetworkAcls.VirtualNetworkResourceIds.Count } else { 0 }
            
            # Check for private endpoints
            $privateEndpoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $kvDetails.ResourceId -ErrorAction SilentlyContinue
            $peCount = if ($privateEndpoints) { $privateEndpoints.Count } else { 0 }
            
            # Determine accessibility status
            $accessibilityStatus = ""
            $statusColor = "White"
            
            if ($publicAccess -eq "Enabled" -and $defaultAction -eq "Allow") {
                $accessibilityStatus = "PUBLICLY ACCESSIBLE"
                $statusColor = "Red"
                $publicKV++
                Write-Host "      ✗ PUBLICLY ACCESSIBLE" -ForegroundColor Red
                
            } elseif ($publicAccess -eq "Enabled" -and $defaultAction -eq "Deny" -and $ipRules -eq 0 -and $vnetRules -eq 0) {
                $accessibilityStatus = "Limited (No allow rules configured)"
                $statusColor = "Yellow"
                Write-Host "      ⚠ Limited - No allow rules" -ForegroundColor Yellow
                
            } elseif ($publicAccess -eq "Enabled" -and $defaultAction -eq "Deny") {
                $accessibilityStatus = "Limited (Firewall restricted)"
                $statusColor = "Yellow"
                Write-Host "      ⚠ Limited - Firewall enabled" -ForegroundColor Yellow
                
            } elseif ($publicAccess -eq "Disabled" -and $peCount -gt 0) {
                $accessibilityStatus = "Private Only"
                $statusColor = "Green"
                Write-Host "      ✓ Private endpoints only" -ForegroundColor Green
                
            } elseif ($publicAccess -eq "Disabled" -and $peCount -eq 0) {
                $accessibilityStatus = "Limited (No private endpoints)"
                $statusColor = "Yellow"
                Write-Host "      ⚠ Disabled - No private endpoints" -ForegroundColor Yellow
                
            } else {
                $accessibilityStatus = "Unknown configuration"
                $statusColor = "Yellow"
                Write-Host "      ? Unknown" -ForegroundColor Yellow
            }
            
            # Add to results
            $results += [PSCustomObject]@{
                Subscription = $subName
                ResourceGroup = $rgName
                KeyVaultName = $kvName
                Location = $location
                AccessibilityStatus = $accessibilityStatus
                PublicNetworkAccess = $publicAccess
                DefaultAction = $defaultAction
                IPRules = $ipRules
                VNetRules = $vnetRules
                PrivateEndpoints = $peCount
            }
            
        } catch {
            Write-Host "      ✗ Failed to retrieve details: $($_.Exception.Message)" -ForegroundColor Red
            
            # Add error entry
            $results += [PSCustomObject]@{
                Subscription = $subName
                ResourceGroup = $rgName
                KeyVaultName = $kvName
                Location = $location
                AccessibilityStatus = "ERROR - Unable to retrieve details"
                PublicNetworkAccess = "Unknown"
                DefaultAction = "Unknown"
                IPRules = 0
                VNetRules = 0
                PrivateEndpoints = 0
            }
        }
    }
    Write-Host ""
}

# Export to CSV
$results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Audit Complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output file: $csvFile" -ForegroundColor Green
Write-Host ""

# Display summary
$publicCount = ($results | Where-Object { $_.AccessibilityStatus -eq "PUBLICLY ACCESSIBLE" }).Count

if ($publicCount -gt 0) {
    Write-Host "⚠ WARNING: Found $publicCount publicly accessible Key Vault(s)!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Publicly accessible Key Vaults:" -ForegroundColor Yellow
    $results | Where-Object { $_.AccessibilityStatus -eq "PUBLICLY ACCESSIBLE" } | ForEach-Object {
        Write-Host "  - $($_.KeyVaultName) (Subscription: $($_.Subscription))" -ForegroundColor Red
    }
    Write-Host ""
} else {
    Write-Host "✓ No publicly accessible Key Vaults found" -ForegroundColor Green
    Write-Host ""
}

Write-Host "Total Key Vaults scanned: $totalKV" -ForegroundColor Cyan
Write-Host ""
Write-Host "Done!" -ForegroundColor Green
