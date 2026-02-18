#!/bin/bash

# Script to identify and report dangerous RBAC permissions
# Generates separate files for built-in and custom roles with detailed assignment information

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BUILTIN_JSON="builtin_dangerous_roles_${TIMESTAMP}.json"
CUSTOM_JSON="custom_dangerous_roles_${TIMESTAMP}.json"
BUILTIN_REPORT="builtin_dangerous_roles_${TIMESTAMP}.txt"
CUSTOM_REPORT="custom_dangerous_roles_${TIMESTAMP}.txt"
ROLES_SUMMARY="dangerous_roles_summary_${TIMESTAMP}.txt"

echo -e "${BLUE}=== Azure Dangerous RBAC Permissions Analysis ===${NC}"
echo ""

# Get subscription info
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
SUBSCRIPTION_NAME=$(az account show --query name -o tsv)
CURRENT_USER=$(az account show --query user.name -o tsv)

echo -e "${GREEN}Subscription: $SUBSCRIPTION_NAME${NC}"
echo -e "${GREEN}User: $CURRENT_USER${NC}"
echo ""

# Fetch data
echo -e "${BLUE}Fetching role definitions...${NC}"
az role definition list --subscription "$SUBSCRIPTION_ID" -o json > ./.roles_data.json

echo -e "${BLUE}Fetching role assignments...${NC}"
az role assignment list --all --subscription "$SUBSCRIPTION_ID" -o json > ./.assignments_data.json

echo -e "${BLUE}Analyzing dangerous permissions...${NC}"
echo ""

# Create role mapping with dangerous permission flags
jq '[.[] | {
    id: .id,
    id_lower: (.id | ascii_downcase),
    name: .roleName,
    type: .roleType,
    has_role_assign_write: ([.permissions[]?.actions[]? | select(
        . == "Microsoft.Authorization/roleAssignments/write" or
        . == "Microsoft.Authorization/roleAssignments/*" or
        . == "Microsoft.Authorization/*" or
        . == "*"
    )] | length > 0),
    has_role_def_write: ([.permissions[]?.actions[]? | select(
        . == "Microsoft.Authorization/roleDefinitions/write" or
        . == "Microsoft.Authorization/roleDefinitions/*" or
        . == "Microsoft.Authorization/*" or
        . == "*"
    )] | length > 0),
    has_fic_write: ([.permissions[]?.actions[]? | select(
        . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write" or
        . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/*" or
        . == "Microsoft.ManagedIdentity/userAssignedIdentities/*" or
        . == "Microsoft.ManagedIdentity/*" or
        . == "*"
    )] | length > 0),
    dangerous_permissions: [
        (if ([.permissions[]?.actions[]? | select(
            . == "Microsoft.Authorization/roleAssignments/write" or
            . == "Microsoft.Authorization/roleAssignments/*" or
            . == "Microsoft.Authorization/*" or
            . == "*"
        )] | length > 0) then "roleAssignments/write" else empty end),
        (if ([.permissions[]?.actions[]? | select(
            . == "Microsoft.Authorization/roleDefinitions/write" or
            . == "Microsoft.Authorization/roleDefinitions/*" or
            . == "Microsoft.Authorization/*" or
            . == "*"
        )] | length > 0) then "roleDefinitions/write" else empty end),
        (if ([.permissions[]?.actions[]? | select(
            . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write" or
            . == "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/*" or
            . == "Microsoft.ManagedIdentity/userAssignedIdentities/*" or
            . == "Microsoft.ManagedIdentity/*" or
            . == "*"
        )] | length > 0) then "federatedIdentityCredentials/write" else empty end)
    ]
}] | map(select(.dangerous_permissions | length > 0))' ./.roles_data.json > ./.dangerous_roles.json

# Process built-in roles
echo -e "${YELLOW}Processing built-in roles...${NC}"

jq '[.[] | select(.type == "BuiltInRole")]' ./.dangerous_roles.json > ./.builtin_dangerous.json

# Process custom roles
echo -e "${YELLOW}Processing custom roles...${NC}"

jq '[.[] | select(.type == "CustomRole")]' ./.dangerous_roles.json > ./.custom_dangerous.json

# Generate roles summary
echo -e "${YELLOW}Generating roles summary...${NC}"

{
    echo "=========================================="
    echo "Azure Dangerous Roles Summary"
    echo "=========================================="
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Subscription: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"
    echo ""
    echo "This file lists all roles (built-in and custom) that have dangerous permissions."
    echo "For detailed assignment information, see the corresponding JSON/TXT report files."
    echo ""
    
    # Built-in roles with roleAssignments/write
    echo "=========================================="
    echo "BUILT-IN ROLES with roleAssignments/write"
    echo "=========================================="
    jq -r '.[] | select(.type == "BuiltInRole") | select(.has_role_assign_write == true) | .name' ./.dangerous_roles.json | sort -u
    BUILTIN_RA_COUNT=$(jq '[.[] | select(.type == "BuiltInRole") | select(.has_role_assign_write == true)] | length' ./.dangerous_roles.json)
    echo ""
    echo "Total: $BUILTIN_RA_COUNT built-in roles"
    echo ""
    
    # Built-in roles with roleDefinitions/write
    echo "=========================================="
    echo "BUILT-IN ROLES with roleDefinitions/write"
    echo "=========================================="
    jq -r '.[] | select(.type == "BuiltInRole") | select(.has_role_def_write == true) | .name' ./.dangerous_roles.json | sort -u
    BUILTIN_RD_COUNT=$(jq '[.[] | select(.type == "BuiltInRole") | select(.has_role_def_write == true)] | length' ./.dangerous_roles.json)
    echo ""
    echo "Total: $BUILTIN_RD_COUNT built-in roles"
    echo ""
    
    # Built-in roles with federatedIdentityCredentials/write
    echo "=========================================="
    echo "BUILT-IN ROLES with federatedIdentityCredentials/write"
    echo "=========================================="
    jq -r '.[] | select(.type == "BuiltInRole") | select(.has_fic_write == true) | .name' ./.dangerous_roles.json | sort -u
    BUILTIN_FIC_COUNT=$(jq '[.[] | select(.type == "BuiltInRole") | select(.has_fic_write == true)] | length' ./.dangerous_roles.json)
    echo ""
    echo "Total: $BUILTIN_FIC_COUNT built-in roles"
    echo ""
    
    # Custom roles with roleAssignments/write
    echo "=========================================="
    echo "CUSTOM ROLES with roleAssignments/write"
    echo "=========================================="
    CUSTOM_RA=$(jq -r '.[] | select(.type == "CustomRole") | select(.has_role_assign_write == true) | .name' ./.dangerous_roles.json | sort -u)
    if [ -z "$CUSTOM_RA" ]; then
        echo "(none)"
    else
        echo "$CUSTOM_RA"
    fi
    CUSTOM_RA_COUNT=$(jq '[.[] | select(.type == "CustomRole") | select(.has_role_assign_write == true)] | length' ./.dangerous_roles.json)
    echo ""
    echo "Total: $CUSTOM_RA_COUNT custom roles"
    echo ""
    
    # Custom roles with roleDefinitions/write
    echo "=========================================="
    echo "CUSTOM ROLES with roleDefinitions/write"
    echo "=========================================="
    CUSTOM_RD=$(jq -r '.[] | select(.type == "CustomRole") | select(.has_role_def_write == true) | .name' ./.dangerous_roles.json | sort -u)
    if [ -z "$CUSTOM_RD" ]; then
        echo "(none)"
    else
        echo "$CUSTOM_RD"
    fi
    CUSTOM_RD_COUNT=$(jq '[.[] | select(.type == "CustomRole") | select(.has_role_def_write == true)] | length' ./.dangerous_roles.json)
    echo ""
    echo "Total: $CUSTOM_RD_COUNT custom roles"
    echo ""
    
    # Custom roles with federatedIdentityCredentials/write
    echo "=========================================="
    echo "CUSTOM ROLES with federatedIdentityCredentials/write"
    echo "=========================================="
    CUSTOM_FIC=$(jq -r '.[] | select(.type == "CustomRole") | select(.has_fic_write == true) | .name' ./.dangerous_roles.json | sort -u)
    if [ -z "$CUSTOM_FIC" ]; then
        echo "(none)"
    else
        echo "$CUSTOM_FIC"
    fi
    CUSTOM_FIC_COUNT=$(jq '[.[] | select(.type == "CustomRole") | select(.has_fic_write == true)] | length' ./.dangerous_roles.json)
    echo ""
    echo "Total: $CUSTOM_FIC_COUNT custom roles"
    echo ""
    
    # Overall summary
    echo "=========================================="
    echo "OVERALL SUMMARY"
    echo "=========================================="
    echo "Built-in roles with dangerous permissions: $(jq '[.[] | select(.type == "BuiltInRole")] | length' ./.dangerous_roles.json)"
    echo "Custom roles with dangerous permissions: $(jq '[.[] | select(.type == "CustomRole")] | length' ./.dangerous_roles.json)"
    echo "Total dangerous roles: $(jq '. | length' ./.dangerous_roles.json)"
    echo ""
    echo "Breakdown by permission type:"
    echo "  - roleAssignments/write: $BUILTIN_RA_COUNT built-in, $CUSTOM_RA_COUNT custom"
    echo "  - roleDefinitions/write: $BUILTIN_RD_COUNT built-in, $CUSTOM_RD_COUNT custom"
    echo "  - federatedIdentityCredentials/write: $BUILTIN_FIC_COUNT built-in, $CUSTOM_FIC_COUNT custom"
    echo "=========================================="
} > "$ROLES_SUMMARY"

echo -e "${GREEN}Roles summary generated${NC}"
echo ""

# Function to build detailed report
build_report() {
    local role_type=$1
    local roles_file=$2
    local json_output=$3
    local text_output=$4
    
    echo -e "${BLUE}Building report for $role_type roles...${NC}"
    
    # Initialize output arrays
    echo "[]" > ./.findings_temp.json
    
    # Initialize text report
    {
        echo "=========================================="
        echo "Azure Dangerous RBAC Permissions Report"
        echo "Role Type: $role_type"
        echo "=========================================="
        echo "Audit Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "User: $CURRENT_USER"
        echo "Subscription: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"
        echo "=========================================="
        echo ""
    } > "$text_output"
    
    local total_findings=0
    
    # Process each dangerous role
    jq -c '.[]' "$roles_file" | while read -r role; do
        ROLE_ID=$(echo "$role" | jq -r '.id_lower')
        ROLE_NAME=$(echo "$role" | jq -r '.name')
        ROLE_TYPE=$(echo "$role" | jq -r '.type')
        DANGEROUS_PERMS=$(echo "$role" | jq -r '.dangerous_permissions | join(", ")')
        
        # Find all assignments for this role
        ASSIGNMENTS=$(jq -c --arg role_id "$ROLE_ID" '[.[] | select((.roleDefinitionId | ascii_downcase) == $role_id)]' ./.assignments_data.json)
        
        ASSIGNMENT_COUNT=$(echo "$ASSIGNMENTS" | jq '. | length')
        
        if [ "$ASSIGNMENT_COUNT" -gt 0 ]; then
            echo -e "  ${GREEN}$ROLE_NAME${NC} - $ASSIGNMENT_COUNT assignment(s)"
            
            # Add to text report
            {
                echo "========================================"
                echo "Role: $ROLE_NAME"
                echo "Dangerous Permissions: $DANGEROUS_PERMS"
                echo "Total Assignments: $ASSIGNMENT_COUNT"
                echo "========================================"
                echo ""
            } >> "$text_output"
            
            # Process each assignment
            echo "$ASSIGNMENTS" | jq -c '.[]' | while read -r assignment; do
                PRINCIPAL_ID=$(echo "$assignment" | jq -r '.principalId')
                PRINCIPAL_NAME=$(echo "$assignment" | jq -r '.principalName // "Unknown"')
                PRINCIPAL_TYPE=$(echo "$assignment" | jq -r '.principalType')
                SCOPE=$(echo "$assignment" | jq -r '.scope')
                ASSIGNMENT_ID=$(echo "$assignment" | jq -r '.id')
                
                # Get principal details
                PRINCIPAL_DETAILS='{"displayName":"Unknown"}'
                if [ "$PRINCIPAL_TYPE" == "User" ]; then
                    PRINCIPAL_DETAILS=$(az ad user show --id "$PRINCIPAL_ID" -o json 2>/dev/null | jq '{displayName:.displayName, userPrincipalName:.userPrincipalName}' || echo '{"displayName":"Unknown","userPrincipalName":"Unknown"}')
                elif [ "$PRINCIPAL_TYPE" == "ServicePrincipal" ]; then
                    PRINCIPAL_DETAILS=$(az ad sp show --id "$PRINCIPAL_ID" -o json 2>/dev/null | jq '{displayName:.displayName, appId:.appId}' || echo '{"displayName":"Unknown","appId":"Unknown"}')
                elif [ "$PRINCIPAL_TYPE" == "Group" ]; then
                    PRINCIPAL_DETAILS=$(az ad group show --group "$PRINCIPAL_ID" -o json 2>/dev/null | jq '{displayName:.displayName}' || echo '{"displayName":"Unknown"}')
                fi
                
                # Add to text report
                {
                    echo "  Principal: $PRINCIPAL_NAME"
                    echo "  Type: $PRINCIPAL_TYPE"
                    echo "  ID: $PRINCIPAL_ID"
                    echo "  Details: $(echo "$PRINCIPAL_DETAILS" | jq -c .)"
                    echo "  Scope: $SCOPE"
                    echo "  Assignment ID: $ASSIGNMENT_ID"
                    echo "  ---"
                } >> "$text_output"
                
                # Build JSON entry
                FINDING=$(jq -n \
                    --arg role_name "$ROLE_NAME" \
                    --arg role_id "$(echo "$role" | jq -r '.id')" \
                    --arg role_type "$ROLE_TYPE" \
                    --argjson dangerous_perms "$(echo "$role" | jq -c '.dangerous_permissions')" \
                    --arg principal_type "$PRINCIPAL_TYPE" \
                    --arg principal_id "$PRINCIPAL_ID" \
                    --arg principal_name "$PRINCIPAL_NAME" \
                    --argjson principal_details "$PRINCIPAL_DETAILS" \
                    --arg scope "$SCOPE" \
                    --arg assignment_id "$ASSIGNMENT_ID" \
                    '{
                        role: {
                            name: $role_name,
                            id: $role_id,
                            type: $role_type,
                            dangerous_permissions: $dangerous_perms
                        },
                        principal: {
                            type: $principal_type,
                            id: $principal_id,
                            name: $principal_name,
                            details: $principal_details
                        },
                        assignment: {
                            scope: $scope,
                            id: $assignment_id
                        }
                    }')
                
                # Append to findings
                CURRENT=$(cat ./.findings_temp.json)
                echo "$CURRENT" | jq --argjson finding "$FINDING" '. += [$finding]' > ./.findings_temp2.json
                mv ./.findings_temp2.json ./.findings_temp.json
                
                total_findings=$((total_findings + 1))
            done
            
            echo "" >> "$text_output"
        fi
    done
    
    # Build final JSON
    FINAL_COUNT=$(jq '. | length' ./.findings_temp.json)
    
    jq -n \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg user "$CURRENT_USER" \
        --arg sub_id "$SUBSCRIPTION_ID" \
        --arg sub_name "$SUBSCRIPTION_NAME" \
        --arg role_type "$role_type" \
        --slurpfile findings ./.findings_temp.json \
        '{
            audit_timestamp: $timestamp,
            user: $user,
            subscription_id: $sub_id,
            subscription_name: $sub_name,
            role_type: $role_type,
            findings: $findings[0],
            summary: {
                total_dangerous_assignments: ($findings[0] | length)
            }
        }' > "$json_output"
    
    # Add summary to text report
    {
        echo "========================================"
        echo "SUMMARY"
        echo "========================================"
        echo "Total dangerous assignments found: $FINAL_COUNT"
        echo "========================================"
    } >> "$text_output"
    
    echo -e "${GREEN}Found $FINAL_COUNT dangerous assignments for $role_type roles${NC}"
}

# Build reports for both types
build_report "Built-in" "./.builtin_dangerous.json" "$BUILTIN_JSON" "$BUILTIN_REPORT"
echo ""
build_report "Custom" "./.custom_dangerous.json" "$CUSTOM_JSON" "$CUSTOM_REPORT"

# Cleanup
rm -f ./.roles_data.json ./.assignments_data.json ./.dangerous_roles.json
rm -f ./.builtin_dangerous.json ./.custom_dangerous.json ./.findings_temp.json

echo ""
echo -e "${GREEN}=== Analysis Complete ===${NC}"
echo ""
echo -e "${BLUE}Output Files:${NC}"
echo -e "  ${YELLOW}Roles Summary: ${GREEN}$ROLES_SUMMARY${NC}"
echo -e "  Built-in Roles JSON: ${GREEN}$BUILTIN_JSON${NC}"
echo -e "  Built-in Roles Report: ${GREEN}$BUILTIN_REPORT${NC}"
echo -e "  Custom Roles JSON: ${GREEN}$CUSTOM_JSON${NC}"
echo -e "  Custom Roles Report: ${GREEN}$CUSTOM_REPORT${NC}"
