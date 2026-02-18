<#
.SYNOPSIS
    Detects guest invite settings in Azure AD (Microsoft Entra ID)

.DESCRIPTION
    This script retrieves and displays the current guest user access settings
    and external collaboration settings in Azure AD, including who can invite
    guests and what permissions guests have.

.NOTES
    Designed for Azure Cloud Shell
    Required Permissions: Policy.Read.All or Directory.Read.All
#>

Write-Host "Using Cloud Shell authentication..." -ForegroundColor Cyan

# Get Tenant ID
$tenantId = az account show --query tenantId -o tsv
Write-Host "Tenant ID: $tenantId" -ForegroundColor Cyan

try {
    # Get Authorization Policy using Azure CLI REST API
    Write-Host "`nRetrieving Azure AD Authorization Policy..." -ForegroundColor Cyan
    $authPolicyJson = az rest --method GET --uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to retrieve authorization policy"
    }
    
    $authPolicy = $authPolicyJson | ConvertFrom-Json

    # Prepare output file
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $outputFile = "azure-guest-settings-$timestamp.txt"
    
    # Start building output content
    $output = @()
    $output += "========================================"
    $output += "AZURE AD GUEST INVITE SETTINGS REPORT"
    $output += "========================================"
    $output += ""
    $output += "Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output += "Tenant ID: $tenantId"
    $output += ""

    # Display Guest Invite Settings
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "GUEST INVITE SETTINGS" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    $output += "========================================"
    $output += "GUEST INVITE SETTINGS"
    $output += "========================================"
    $output += ""

    Write-Host "`nGuest User Access Restrictions:" -ForegroundColor Yellow
    $output += "Guest User Access Restrictions:"
    
    switch ($authPolicy.guestUserRoleId) {
        "a0b1b346-4d3e-4e8b-98f8-753987be4970" {
            Write-Host "  Level: Same as member users (most permissive)" -ForegroundColor White
            $output += "  Level: Same as member users (most permissive)"
        }
        "10dae51f-b6af-4016-8d66-8c2a99b929b3" {
            Write-Host "  Level: Limited access (default)" -ForegroundColor White
            $output += "  Level: Limited access (default)"
        }
        "2af84b1e-32c8-42b7-82bc-daa82404023b" {
            Write-Host "  Level: Restricted access (most restrictive)" -ForegroundColor White
            $output += "  Level: Restricted access (most restrictive)"
        }
        default {
            Write-Host "  Level: Custom ($($authPolicy.guestUserRoleId))" -ForegroundColor White
            $output += "  Level: Custom ($($authPolicy.guestUserRoleId))"
        }
    }
    $output += ""

    Write-Host "`nWho Can Invite Guests:" -ForegroundColor Yellow
    Write-Host "  Allow Invitations From: $($authPolicy.allowInvitesFrom)" -ForegroundColor White
    
    $output += "Who Can Invite Guests:"
    $output += "  Allow Invitations From: $($authPolicy.allowInvitesFrom)"
    
    switch ($authPolicy.allowInvitesFrom) {
        "everyone" {
            Write-Host "    → All users in the organization can invite guests" -ForegroundColor Gray
            $output += "    → All users in the organization can invite guests"
        }
        "adminsAndGuestInviters" {
            Write-Host "    → Only admins and users with Guest Inviter role can invite" -ForegroundColor Gray
            $output += "    → Only admins and users with Guest Inviter role can invite"
        }
        "adminsGuestInvitersAndAllMembers" {
            Write-Host "    → Admins, Guest Inviters, and all members can invite (guests cannot)" -ForegroundColor Gray
            $output += "    → Admins, Guest Inviters, and all members can invite (guests cannot)"
        }
        "none" {
            Write-Host "    → No one can invite guests" -ForegroundColor Gray
            $output += "    → No one can invite guests"
        }
    }
    $output += ""

    Write-Host "`nGuest User Permissions:" -ForegroundColor Yellow
    Write-Host "  Block MSOL PowerShell: $($authPolicy.blockMsolPowerShell)" -ForegroundColor White
    
    $output += "Guest User Permissions:"
    $output += "  Block MSOL PowerShell: $($authPolicy.blockMsolPowerShell)"
    $output += ""

    # Additional collaboration settings
    Write-Host "`nExternal Collaboration Settings:" -ForegroundColor Yellow
    Write-Host "  Allowed To Sign Up Email Based Subscriptions: $($authPolicy.allowedToSignUpEmailBasedSubscriptions)" -ForegroundColor White
    Write-Host "  Allowed Email Verified Users To Join Organization: $($authPolicy.allowEmailVerifiedUsersToJoinOrganization)" -ForegroundColor White

    $output += "External Collaboration Settings:"
    $output += "  Allowed To Sign Up Email Based Subscriptions: $($authPolicy.allowedToSignUpEmailBasedSubscriptions)"
    $output += "  Allowed Email Verified Users To Join Organization: $($authPolicy.allowEmailVerifiedUsersToJoinOrganization)"
    $output += ""

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "SUMMARY" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    $output += "========================================"
    $output += "SUMMARY"
    $output += "========================================"
    $output += ""
    
    $guestRestrictionLevel = switch ($authPolicy.guestUserRoleId) {
        "a0b1b346-4d3e-4e8b-98f8-753987be4970" { "Least Restrictive" }
        "10dae51f-b6af-4016-8d66-8c2a99b929b3" { "Moderately Restrictive" }
        "2af84b1e-32c8-42b7-82bc-daa82404023b" { "Most Restrictive" }
        default { "Custom" }
    }

    Write-Host "`nGuest Access Level: $guestRestrictionLevel" -ForegroundColor Cyan
    Write-Host "Invite Policy: $($authPolicy.allowInvitesFrom)" -ForegroundColor Cyan
    
    $output += "Guest Access Level: $guestRestrictionLevel"
    $output += "Invite Policy: $($authPolicy.allowInvitesFrom)"
    $output += ""
    
    # Only show warning if policy is 'everyone'
    if ($authPolicy.allowInvitesFrom -eq "everyone") {
        Write-Host "`n⚠️  WARNING: All users can invite guests - consider restricting this" -ForegroundColor Red
        $output += "⚠️  WARNING: All users can invite guests - consider restricting this"
        $output += ""
    }
    
    # Write to file
    $output | Out-File -FilePath $outputFile -Encoding UTF8
    
    Write-Host "`nReport saved to: $outputFile" -ForegroundColor Green

} catch {
    Write-Host "`nError retrieving guest settings: $_" -ForegroundColor Red
    Write-Host "Make sure you have the required permissions (Policy.Read.All or Directory.Read.All)" -ForegroundColor Yellow
}

Write-Host "`nScript completed." -ForegroundColor Cyan
