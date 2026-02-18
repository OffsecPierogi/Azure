$response = Invoke-AzRestMethod -Method GET `
  -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"

$policy = ($response.Content | ConvertFrom-Json)

$settingsResponse = Invoke-AzRestMethod -Method GET `
  -Uri "https://graph.microsoft.com/beta/settings"

$settings = ($settingsResponse.Content | ConvertFrom-Json).value

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host " Entra ID User Settings Report" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "--- Default User Role Permissions ---" -ForegroundColor Yellow
Write-Host "Users can register applications          : $($policy.defaultUserRolePermissions.allowedToCreateApps)"
Write-Host "Restrict non-admins from creating tenants: $($policy.defaultUserRolePermissions.allowedToCreateTenants)"
Write-Host "Users can create security groups         : $($policy.defaultUserRolePermissions.allowedToCreateSecurityGroups)"

Write-Host ""
Write-Host "--- Guest User Access ---" -ForegroundColor Yellow
$guestRoleMap = @{
    "a0b1b346-4d3e-4e8b-98f8-753987be4970" = "Same access as members (most inclusive)"
    "10dae51f-b6af-4016-8d66-8c2a99b929b3" = "Limited access to properties and memberships"
    "2af84b1e-32c8-42b7-82bc-daa82404023b" = "Restricted to own directory objects (most restrictive)"
}
Write-Host "Guest access restriction                 : $($guestRoleMap[$policy.guestUserRoleId])"

Write-Host ""
Write-Host "--- Administration Center ---" -ForegroundColor Yellow
$restrict = $settings |
  Where-Object { $_.displayName -eq "Authorization Policy" } |
  ForEach-Object { $_.values | Where-Object { $_.name -eq "RestrictNonAdminUsers" } } |
  Select-Object -ExpandProperty value

if (-not $restrict) {
  $restrict = "false (default - not restricted)"
}
Write-Host "Restrict access to Entra admin center    : $restrict"

Write-Host ""
