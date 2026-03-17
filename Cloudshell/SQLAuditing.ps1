# =============================================================================
# Azure SQL Auditing Status Check Script
# Loops through ALL accessible subscriptions
# Flags server-level auditing, and only flags databases if their server
# does not have auditing enabled
# Run from Azure Cloud Shell (PowerShell)
# =============================================================================

$OutputFile = "sql_auditing_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Azure SQL Auditing Status Check" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# Results collection
$results = @()

# Get all accessible subscriptions
Write-Host "Fetching all accessible subscriptions..."
$subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }

Write-Host "Found $($subscriptions.Count) subscription(s)"
Write-Host ""

foreach ($sub in $subscriptions) {
    $subName = $sub.Name
    $subId = $sub.Id
    
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "SUBSCRIPTION: $subName" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    
    # Set the current subscription
    Set-AzContext -SubscriptionId $subId | Out-Null
    
    # Get all SQL servers in this subscription
    $servers = Get-AzSqlServer -ErrorAction SilentlyContinue
    
    if ($servers.Count -eq 0) {
        Write-Host "No SQL Servers found." -ForegroundColor Yellow
        continue
    }
    
    foreach ($server in $servers) {
        $serverName = $server.ServerName
        $rg = $server.ResourceGroupName
        
        # Check server-level auditing
        try {
            $serverAudit = Get-AzSqlServerAudit -ResourceGroupName $rg -ServerName $serverName
            $serverAuditEnabled = ($serverAudit.BlobStorageTargetState -eq "Enabled" -or 
                                   $serverAudit.LogAnalyticsTargetState -eq "Enabled" -or 
                                   $serverAudit.EventHubTargetState -eq "Enabled")
        }
        catch {
            $serverAuditEnabled = $false
        }
        
        if ($serverAuditEnabled) {
            $serverStatus = "Enabled"
            Write-Host "[✓] Server: $serverName - Auditing ENABLED" -ForegroundColor Green
        }
        else {
            $serverStatus = "Disabled"
            Write-Host "[✗] Server: $serverName - Auditing DISABLED" -ForegroundColor Red
        }
        
        # Add server to results
        $results += [PSCustomObject]@{
            "Asset Name"       = $serverName
            "Asset Type"       = "SQL Server"
            "Auditing Status"  = $serverStatus
            "Subscription"     = $subName
        }
        
        # Only check databases if server auditing is DISABLED
        if (-not $serverAuditEnabled) {
            $databases = Get-AzSqlDatabase -ResourceGroupName $rg -ServerName $serverName | 
                         Where-Object { $_.DatabaseName -ne "master" }
            
            foreach ($db in $databases) {
                $dbName = $db.DatabaseName
                
                try {
                    $dbAudit = Get-AzSqlDatabaseAudit -ResourceGroupName $rg -ServerName $serverName -DatabaseName $dbName
                    $dbAuditEnabled = ($dbAudit.BlobStorageTargetState -eq "Enabled" -or 
                                       $dbAudit.LogAnalyticsTargetState -eq "Enabled" -or 
                                       $dbAudit.EventHubTargetState -eq "Enabled")
                }
                catch {
                    $dbAuditEnabled = $false
                }
                
                if ($dbAuditEnabled) {
                    $dbStatus = "Enabled"
                    Write-Host "    [✓] Database: $dbName - Auditing ENABLED" -ForegroundColor Green
                }
                else {
                    $dbStatus = "Disabled"
                    Write-Host "    [✗] Database: $dbName - Auditing DISABLED (NOT COVERED)" -ForegroundColor Red
                }
                
                # Add database to results
                $results += [PSCustomObject]@{
                    "Asset Name"       = $dbName
                    "Asset Type"       = "SQL Database"
                    "Auditing Status"  = $dbStatus
                    "Subscription"     = $subName
                }
            }
        }
    }
    Write-Host ""
}

# Export to CSV
$results | Export-Csv -Path $OutputFile -NoTypeInformation

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Scan Complete" -ForegroundColor Cyan
Write-Host "Report exported to: $OutputFile" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
$results | Format-Table -AutoSize
