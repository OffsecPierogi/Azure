 
#!/bin/bash

# Script to list custom & built-in Azure roles with dangerous permissions

echo "=== Built-in Azure Roles with Dangerous Permissions ==="
echo ""

SUBSCRIPTION_ID=$(az account show --query id -o tsv)

echo "Fetching role definitions..."
az role definition list --subscription "$SUBSCRIPTION_ID" -o json > ./.roles_check.json

echo ""
echo "=========================================="
echo "BUILT-IN ROLES WITH roleAssignments/write"
echo "=========================================="
jq -r '.[] | select(.roleType == "BuiltInRole") | select(.permissions[]?.actions[]? | 
    . == "Microsoft.Authorization/roleAssignments/write" or
    . == "Microsoft.Authorization/roleAssignments/*" or
    . == "Microsoft.Authorization/*" or
    . == "*") | 
    .roleName' ./.roles_check.json | sort -u

echo ""
echo "=========================================="
echo "BUILT-IN ROLES WITH roleDefinitions/write"
echo "=========================================="
jq -r '.[] | select(.roleType == "BuiltInRole") | select(.permissions[]?.actions[]? | 
    . == "Microsoft.Authorization/roleDefinitions/write" or
    . == "Microsoft.Authorization/roleDefinitions/*" or
    . == "Microsoft.Authorization/*" or
    . == "*") | 
    .roleName' ./.roles_check.json | sort -u

echo ""
echo "=========================================="
echo "BUILT-IN ROLES WITH federatedIdentityCredentials/write"
echo "=========================================="
jq -r '.[] | select(.roleType == "BuiltInRole") | select(.permissions[]?.actions[]? | 
    . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write" or
    . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/*" or
    . == "Microsoft.ManagedIdentity/userAssignedIdentities/*" or
    . == "Microsoft.ManagedIdentity/*" or
    . == "*") | 
    .roleName' ./.roles_check.json | sort -u

echo ""
echo "=========================================="
echo "CUSTOM ROLES WITH DANGEROUS PERMISSIONS"
echo "=========================================="
echo ""
echo "Custom roles with roleAssignments/write:"
jq -r '.[] | select(.roleType == "CustomRole") | select(.permissions[]?.actions[]? | 
    . == "Microsoft.Authorization/roleAssignments/write" or
    . == "Microsoft.Authorization/roleAssignments/*" or
    . == "Microsoft.Authorization/*" or
    . == "*") | 
    .roleName' ./.roles_check.json | sort -u

echo ""
echo "Custom roles with roleDefinitions/write:"
jq -r '.[] | select(.roleType == "CustomRole") | select(.permissions[]?.actions[]? | 
    . == "Microsoft.Authorization/roleDefinitions/write" or
    . == "Microsoft.Authorization/roleDefinitions/*" or
    . == "Microsoft.Authorization/*" or
    . == "*") | 
    .roleName' ./.roles_check.json | sort -u

echo ""
echo "Custom roles with federatedIdentityCredentials/write:"
jq -r '.[] | select(.roleType == "CustomRole") | select(.permissions[]?.actions[]? | 
    . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write" or
    . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/*" or
    . == "Microsoft.ManagedIdentity/userAssignedIdentities/*" or
    . == "Microsoft.ManagedIdentity/*" or
    . == "*") | 
    .roleName' ./.roles_check.json | sort -u

echo ""
echo "=========================================="
echo "ROLE COUNTS"
echo "=========================================="
BUILTIN_RA=$(jq '[.[] | select(.roleType == "BuiltInRole") | select(.permissions[]?.actions[]? | . == "Microsoft.Authorization/roleAssignments/write" or . == "Microsoft.Authorization/roleAssignments/*" or . == "Microsoft.Authorization/*" or . == "*")] | length' ./.roles_check.json)
BUILTIN_RD=$(jq '[.[] | select(.roleType == "BuiltInRole") | select(.permissions[]?.actions[]? | . == "Microsoft.Authorization/roleDefinitions/write" or . == "Microsoft.Authorization/roleDefinitions/*" or . == "Microsoft.Authorization/*" or . == "*")] | length' ./.roles_check.json)
BUILTIN_FIC=$(jq '[.[] | select(.roleType == "BuiltInRole") | select(.permissions[]?.actions[]? | . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write" or . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/*" or . == "Microsoft.ManagedIdentity/userAssignedIdentities/*" or . == "Microsoft.ManagedIdentity/*" or . == "*")] | length' ./.roles_check.json)

CUSTOM_RA=$(jq '[.[] | select(.roleType == "CustomRole") | select(.permissions[]?.actions[]? | . == "Microsoft.Authorization/roleAssignments/write" or . == "Microsoft.Authorization/roleAssignments/*" or . == "Microsoft.Authorization/*" or . == "*")] | length' ./.roles_check.json)
CUSTOM_RD=$(jq '[.[] | select(.roleType == "CustomRole") | select(.permissions[]?.actions[]? | . == "Microsoft.Authorization/roleDefinitions/write" or . == "Microsoft.Authorization/roleDefinitions/*" or . == "Microsoft.Authorization/*" or . == "*")] | length' ./.roles_check.json)
CUSTOM_FIC=$(jq '[.[] | select(.roleType == "CustomRole") | select(.permissions[]?.actions[]? | . == "Microsoft.Authorization/federatedIdentityCredentials/write" or . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/*" or . == "Microsoft.ManagedIdentity/userAssignedIdentities/*" or . == "Microsoft.ManagedIdentity/*" or . == "*")] | length' ./.roles_check.json)

echo "Built-in roles with roleAssignments/write: $BUILTIN_RA"
echo "Built-in roles with roleDefinitions/write: $BUILTIN_RD"
echo "Built-in roles with federatedIdentityCredentials/write: $BUILTIN_FIC"
echo ""
echo "Custom roles with roleAssignments/write: $CUSTOM_RA"
echo "Custom roles with roleDefinitions/write: $CUSTOM_RD"
echo "Custom roles with federatedIdentityCredentials/write: $CUSTOM_FIC"

rm -f ./.roles_check.json
