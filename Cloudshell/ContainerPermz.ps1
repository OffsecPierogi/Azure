$permOutput = "Container_permissions.csv"
$identityOutput = "containerassets_identity.csv"

"Subscription,ObjectName,ObjectType,Permission,ResourceName" | Out-File $permOutput
"Subscription,ContainerResource,IdentityEnabled,IdentityType" | Out-File $identityOutput

Write-Host "[*] Enumerating all accessible subscriptions..."
$subscriptions = az account list | ConvertFrom-Json

foreach ($sub in $subscriptions) {

    $subName = $sub.name
    Write-Host "`n[*] Switching to subscription: $subName"
    az account set --subscription $subName | Out-Null

    ############################################
    # ROLE ASSIGNMENTS – CONTAINER ONLY
    ############################################

    $assignments = az role assignment list --all | ConvertFrom-Json

    foreach ($assignment in $assignments) {

        $scope = $assignment.scope
        $roleName = $assignment.roleDefinitionName
        $principalType = $assignment.principalType
        $principalId = $assignment.principalId

        # STRICT container filtering
        if ($scope -notmatch "^/subscriptions/" -and
            $scope -notmatch "Microsoft.ContainerRegistry" -and
            $scope -notmatch "Microsoft.App" -and
            $scope -notmatch "Microsoft.ContainerInstance") {
            continue
        }

        # Explicitly ignore Key Vault
        if ($scope -match "Microsoft.KeyVault") {
            continue
        }

        # Resource name handling
        if ($scope -match "^/subscriptions/[^/]+$") {
            $resourceName = $subName
        }
        else {
            $resourceName = ($scope -split "/")[-1]
        }

        # Resolve principal name
        $objectName = "Unknown"

        try {
            $objectName = (az ad user show --id $principalId | ConvertFrom-Json).userPrincipalName
        } catch {}

        if ($objectName -eq $null -or $objectName -eq "") {
            try {
                $objectName = (az ad sp show --id $principalId | ConvertFrom-Json).displayName
            } catch {}
        }

        if ($objectName -eq $null -or $objectName -eq "") {
            try {
                $objectName = (az ad group show --id $principalId | ConvertFrom-Json).displayName
            } catch {}
        }

        if ($objectName -eq $null -or $objectName -eq "") {
            $objectName = "Unknown"
        }

        ########################################
        # Owner / Contributor implicit
        ########################################

        if ($roleName -eq "Owner" -or $roleName -eq "Contributor") {
            "$subName,$objectName,$principalType,$roleName (implicit full write),$resourceName" |
                Out-File $permOutput -Append
            continue
        }

        ########################################
        # Explicit container write permissions
        ########################################

        $roleDef = az role definition list --name $roleName | ConvertFrom-Json

        foreach ($perm in $roleDef.permissions.actions) {

            if ($perm -eq "*" -or
                $perm -like "*ContainerRegistry/registries/push*" -or
                $perm -like "*ContainerRegistry/*" -or
                $perm -eq "Microsoft.App/jobs/write" -or
                $perm -eq "Microsoft.App/jobs/listSecrets/action" -or
                $perm -eq "Microsoft.App/containerApps/write" -or
                $perm -eq "Microsoft.ContainerInstance/containerGroups/write" -or
                $perm -eq "Microsoft.ContainerInstance/containerGroups/containers/exec/action") {

                "$subName,$objectName,$principalType,$perm,$resourceName" |
                    Out-File $permOutput -Append
            }
        }
    }

    ############################################
    # CONTAINER ASSETS – IDENTITY CHECK
    ############################################

    Write-Host "[*] Checking Container Apps..."
    $apps = az containerapp list | ConvertFrom-Json
    foreach ($app in $apps) {
        if ($app.identity -and $app.identity.type) {
            "$subName,$($app.name),Yes,$($app.identity.type)" |
                Out-File $identityOutput -Append
        }
    }

    Write-Host "[*] Checking Container Instances..."
    $groups = az container list | ConvertFrom-Json
    foreach ($group in $groups) {
        if ($group.identity -and $group.identity.type) {
            "$subName,$($group.name),Yes,$($group.identity.type)" |
                Out-File $identityOutput -Append
        }
    }
}

Write-Host "`n================ PERMISSION RESULTS ================"
Import-Csv $permOutput | Format-Table -AutoSize

Write-Host "`n================ CONTAINER ASSETS WITH IDENTITIES ================"
Import-Csv $identityOutput | Format-Table -AutoSize

Write-Host "`nCSV Files Created:"
Write-Host $permOutput
Write-Host $identityOutput
