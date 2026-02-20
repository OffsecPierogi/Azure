#!/bin/bash

PERM_OUTPUT="Container_permissions.csv"
IDENTITY_OUTPUT="containerassets_identity.csv"

echo "Subscription,ObjectName,ObjectType,Permission,ResourceName" > $PERM_OUTPUT
echo "Subscription,ContainerResource,IdentityEnabled,IdentityType" > $IDENTITY_OUTPUT

echo "[*] Enumerating all accessible subscriptions..."
echo ""

SUBSCRIPTIONS=$(az account list --query "[].name" -o tsv)

for SUB in $SUBSCRIPTIONS; do

    echo "[*] Switching to subscription: $SUB"
    az account set --subscription "$SUB" >/dev/null

    ############################################
    # ROLE ASSIGNMENTS – CONTAINER ONLY
    ############################################

    az role assignment list --all -o json | jq -c '.[]' | while read assignment; do

        PRINCIPAL_ID=$(echo $assignment | jq -r '.principalId')
        PRINCIPAL_TYPE=$(echo $assignment | jq -r '.principalType')
        ROLE_NAME=$(echo $assignment | jq -r '.roleDefinitionName')
        SCOPE=$(echo $assignment | jq -r '.scope')

        # STRICT container scope filtering
        if [[ "$SCOPE" != "/subscriptions/"* &&
              "$SCOPE" != *"Microsoft.ContainerRegistry"* &&
              "$SCOPE" != *"Microsoft.App"* &&
              "$SCOPE" != *"Microsoft.ContainerInstance"* ]]; then
            continue
        fi

        # EXPLICITLY ignore KeyVault
        if [[ "$SCOPE" == *"Microsoft.KeyVault"* ]]; then
            continue
        fi

        # Resource name handling
        if [[ "$SCOPE" =~ ^/subscriptions/[^/]+$ ]]; then
            RESOURCE_NAME="$SUB"
        else
            RESOURCE_NAME=$(echo "$SCOPE" | awk -F'/' '{print $NF}')
        fi

        # Resolve principal name
        OBJECT_NAME=""
        if [ "$PRINCIPAL_TYPE" == "ServicePrincipal" ]; then
            OBJECT_NAME=$(az ad sp show --id $PRINCIPAL_ID --query displayName -o tsv 2>/dev/null)
        elif [ "$PRINCIPAL_TYPE" == "User" ]; then
            OBJECT_NAME=$(az ad user show --id $PRINCIPAL_ID --query userPrincipalName -o tsv 2>/dev/null)
        elif [ "$PRINCIPAL_TYPE" == "Group" ]; then
            OBJECT_NAME=$(az ad group show --id $PRINCIPAL_ID --query displayName -o tsv 2>/dev/null)
        fi

        [ -z "$OBJECT_NAME" ] && OBJECT_NAME="Unknown"

        # Owner / Contributor implicit
        if [[ "$ROLE_NAME" == "Owner" ]] || [[ "$ROLE_NAME" == "Contributor" ]]; then
            echo "$SUB,$OBJECT_NAME,$PRINCIPAL_TYPE,$ROLE_NAME (implicit full write),$RESOURCE_NAME" >> $PERM_OUTPUT
            continue
        fi

        # Explicit container permissions
        az role definition list --name "$ROLE_NAME" -o json | jq -r '.[] | .permissions[].actions[]?' | while read action; do

            if [[ "$action" == "*" ]] ||
               [[ "$action" == *"Microsoft.ContainerRegistry/registries/push"* ]] ||
               [[ "$action" == *"Microsoft.ContainerRegistry/*" ]] ||
               [[ "$action" == "Microsoft.App/jobs/write" ]] ||
               [[ "$action" == "Microsoft.App/jobs/listSecrets/action" ]] ||
               [[ "$action" == "Microsoft.App/containerApps/write" ]] ||
               [[ "$action" == "Microsoft.ContainerInstance/containerGroups/write" ]] ||
               [[ "$action" == "Microsoft.ContainerInstance/containerGroups/containers/exec/action" ]]; then

                echo "$SUB,$OBJECT_NAME,$PRINCIPAL_TYPE,$action,$RESOURCE_NAME" >> $PERM_OUTPUT
            fi
        done

    done


    ############################################
    # CONTAINER ASSETS – IDENTITY CHECK
    ############################################

    echo "[*] Checking Container Apps..."

    az containerapp list -o json 2>/dev/null | jq -c '.[]?' | while read app; do
        APP_NAME=$(echo $app | jq -r '.name')
        IDENTITY_TYPE=$(echo $app | jq -r '.identity.type // empty')

        if [ -n "$IDENTITY_TYPE" ]; then
            echo "$SUB,$APP_NAME,Yes,$IDENTITY_TYPE" >> $IDENTITY_OUTPUT
        fi
    done

    echo "[*] Checking Container Instances..."

    az container list -o json 2>/dev/null | jq -c '.[]?' | while read group; do
        GROUP_NAME=$(echo $group | jq -r '.name')
        IDENTITY_TYPE=$(echo $group | jq -r '.identity.type // empty')

        if [ -n "$IDENTITY_TYPE" ]; then
            echo "$SUB,$GROUP_NAME,Yes,$IDENTITY_TYPE" >> $IDENTITY_OUTPUT
        fi
    done

done


echo ""
echo "================ PERMISSION RESULTS ================"
column -t -s ',' $PERM_OUTPUT

echo ""
echo "================ CONTAINER ASSETS WITH IDENTITIES ================"
column -t -s ',' $IDENTITY_OUTPUT

echo ""
echo "CSV Files Created:"
echo "$PERM_OUTPUT"
echo "$IDENTITY_OUTPUT"

#ACI & ACR Perms will be enumerated & any roles that can conduct such actions
