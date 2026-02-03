#!/bin/bash

###############################################################################
# Azure Container Registry Permission Enumeration Script
# 
# Identifies high-risk permissions on Azure Container Registries including:
# - Admin credential access
# - Token generation capabilities
# - Task modification with managed identities
# - Registry configuration changes
###############################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# High-risk ACR permissions
declare -A DANGEROUS_PERMISSIONS=(
    ["Microsoft.ContainerRegistry/registries/listCredentials/action"]="List admin credentials (username/password)"
    ["Microsoft.ContainerRegistry/registries/regenerateCredential/action"]="Regenerate admin credentials"
    ["Microsoft.ContainerRegistry/registries/generateCredentials/action"]="Generate repository-scoped tokens"
    ["Microsoft.ContainerRegistry/registries/tokens/write"]="Create/modify repository access tokens"
    ["Microsoft.ContainerRegistry/registries/tokens/delete"]="Delete repository access tokens"
    ["Microsoft.ContainerRegistry/registries/scopeMaps/write"]="Create/modify token scope maps"
    ["Microsoft.ContainerRegistry/registries/tasks/write"]="Create/modify ACR tasks (can use managed identity)"
    ["Microsoft.ContainerRegistry/registries/write"]="Modify registry settings (enable admin account)"
    ["Microsoft.ContainerRegistry/registries/delete"]="Delete entire registry"
    ["Microsoft.ContainerRegistry/registries/webhooks/write"]="Create/modify webhooks (exfiltration risk)"
    ["Microsoft.ContainerRegistry/registries/importImage/action"]="Import images from external registries"
    ["Microsoft.ContainerRegistry/registries/builds/write"]="Trigger builds with custom source code"
    ["Microsoft.ContainerRegistry/registries/agentpools/write"]="Modify agent pools for task execution"
    ["*"]="Full wildcard permissions (Owner/Contributor)"
    ["Microsoft.ContainerRegistry/*"]="All Container Registry permissions"
)

# Output file
OUTPUT_FILE="acr-permissions-$(date +%Y%m%d-%H%M%S).txt"

print_header() {
    echo -e "${CYAN}$1${NC}"
}

print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[*] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[X] $1${NC}"
}

print_finding() {
    echo -e "${RED}  [FINDING] $1${NC}"
}

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    print_error "Azure CLI not found. Please install it first."
    exit 1
fi

# Check if logged in
if ! az account show &> /dev/null; then
    print_error "Not logged into Azure. Run 'az login' first."
    exit 1
fi

CURRENT_USER=$(az account show --query user.name -o tsv)
print_success "Logged in as: $CURRENT_USER"

print_header "\n=== Azure Container Registry Permission Enumeration ==="
print_info "Started: $(date)"
echo ""

# Initialize findings counter
TOTAL_FINDINGS=0
FINDINGS_FILE="/tmp/acr_findings_count_$$.tmp"
echo "0" > "$FINDINGS_FILE"

# Get subscriptions
SUBSCRIPTIONS=$(az account list --query "[].{id:id, name:name}" -o json)
SUB_COUNT=$(echo "$SUBSCRIPTIONS" | jq length)

print_info "Checking $SUB_COUNT subscription(s)..."

# Get current user/principal information
CURRENT_PRINCIPAL=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "Unknown")
CURRENT_USER_OID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "")

# Iterate through subscriptions
echo "$SUBSCRIPTIONS" | jq -c '.[]' | while read -r sub; do
    SUB_ID=$(echo "$sub" | jq -r '.id')
    SUB_NAME=$(echo "$sub" | jq -r '.name')
    
    az account set --subscription "$SUB_ID" 2>/dev/null || continue
    
    print_header "\n--- Subscription: $SUB_NAME ($SUB_ID) ---"
    
    # Get all ACRs in subscription
    REGISTRIES=$(az acr list --query "[].{name:name, resourceGroup:resourceGroup, id:id, loginServer:loginServer, adminUserEnabled:adminUserEnabled}" -o json 2>/dev/null || echo "[]")
    REGISTRY_COUNT=$(echo "$REGISTRIES" | jq length)
    
    if [ "$REGISTRY_COUNT" -eq 0 ]; then
        print_info "No container registries found"
        continue
    fi
    
    print_success "Found $REGISTRY_COUNT container registry(ies)"
    
    # Iterate through registries
    echo "$REGISTRIES" | jq -c '.[]' | while read -r registry; do
        REG_NAME=$(echo "$registry" | jq -r '.name')
        REG_RG=$(echo "$registry" | jq -r '.resourceGroup')
        REG_ID=$(echo "$registry" | jq -r '.id')
        LOGIN_SERVER=$(echo "$registry" | jq -r '.loginServer')
        ADMIN_ENABLED=$(echo "$registry" | jq -r '.adminUserEnabled')
        
        echo -e "\n${YELLOW}Registry: $REG_NAME${NC}"
        echo -e "${GRAY}  Resource Group: $REG_RG${NC}"
        echo -e "${GRAY}  Login Server: $LOGIN_SERVER${NC}"
        echo -e "${GRAY}  Admin User Enabled: $ADMIN_ENABLED${NC}"
        
        # Get role assignments for this registry
        print_info "  Checking permissions..."
        
        ROLE_ASSIGNMENTS=$(az role assignment list --scope "$REG_ID" --all --query "[].{principalName:principalName, principalId:principalId, principalType:principalType, roleDefinitionName:roleDefinitionName, roleDefinitionId:roleDefinitionId, scope:scope}" -o json 2>/dev/null || echo "[]")
        
        # Check each role assignment
        REGISTRY_FINDINGS=0
        
        # Create a temporary file to track findings in this subshell
        TEMP_FINDINGS="/tmp/registry_findings_$$.tmp"
        echo "0" > "$TEMP_FINDINGS"
        
        echo "$ROLE_ASSIGNMENTS" | jq -c '.[]' | while read -r assignment; do
            ROLE_NAME=$(echo "$assignment" | jq -r '.roleDefinitionName')
            ROLE_ID=$(echo "$assignment" | jq -r '.roleDefinitionId')
            PRINCIPAL=$(echo "$assignment" | jq -r '.principalName')
            PRINCIPAL_ID=$(echo "$assignment" | jq -r '.principalId')
            PRINCIPAL_TYPE=$(echo "$assignment" | jq -r '.principalType')
            SCOPE=$(echo "$assignment" | jq -r '.scope')
            
            # Get role definition with permissions
            ROLE_DEF=$(az role definition list --name "$ROLE_NAME" --query "[0].permissions[0].actions" -o json 2>/dev/null || echo "[]")
            
            # Check for dangerous permissions
            for permission in "${!DANGEROUS_PERMISSIONS[@]}"; do
                if echo "$ROLE_DEF" | jq -e --arg perm "$permission" 'any(. == $perm)' > /dev/null 2>&1; then
                    print_finding "$permission"
                    echo -e "${YELLOW}    Description: ${DANGEROUS_PERMISSIONS[$permission]}${NC}"
                    echo -e "${GRAY}    Via Role: $ROLE_NAME${NC}"
                    echo -e "${GRAY}    Principal: $PRINCIPAL (${PRINCIPAL_TYPE})${NC}"
                    echo -e "${GRAY}    Principal ID: $PRINCIPAL_ID${NC}"
                    echo -e "${GRAY}    Scope: $SCOPE${NC}"
                    
                    # Log to file
                    {
                        echo "SUBSCRIPTION: $SUB_NAME"
                        echo "REGISTRY: $REG_NAME"
                        echo "RESOURCE GROUP: $REG_RG"
                        echo "PERMISSION: $permission"
                        echo "DESCRIPTION: ${DANGEROUS_PERMISSIONS[$permission]}"
                        echo "ROLE: $ROLE_NAME"
                        echo "PRINCIPAL: $PRINCIPAL"
                        echo "PRINCIPAL_TYPE: $PRINCIPAL_TYPE"
                        echo "PRINCIPAL_ID: $PRINCIPAL_ID"
                        echo "SCOPE: $SCOPE"
                        echo "ADMIN ENABLED: $ADMIN_ENABLED"
                        echo "---"
                    } >> "$OUTPUT_FILE"
                    
                    # Increment findings counter
                    CURRENT_COUNT=$(cat "$TEMP_FINDINGS")
                    echo $((CURRENT_COUNT + 1)) > "$TEMP_FINDINGS"
                    
                    # Update global counter
                    GLOBAL_COUNT=$(cat "$FINDINGS_FILE")
                    echo $((GLOBAL_COUNT + 1)) > "$FINDINGS_FILE"
                fi
            done
        done
        
        REGISTRY_FINDINGS=$(cat "$TEMP_FINDINGS" 2>/dev/null || echo "0")
        rm -f "$TEMP_FINDINGS"
        
        if [ "$REGISTRY_FINDINGS" -eq 0 ]; then
            print_success "  No high-risk role-based permissions found"
        else
            print_warning "  Found $REGISTRY_FINDINGS high-risk role-based permission(s)"
        fi
        
        # Additional security checks
        print_info "\n  Additional Security Checks:"
        
        # Check for tokens
        TOKENS=$(az acr token list --registry "$REG_NAME" --resource-group "$REG_RG" --query "length(@)" -o tsv 2>/dev/null || echo "0")
        if [ "$TOKENS" != "0" ]; then
            print_warning "    Found $TOKENS repository token(s)"
        fi
        
        # Check for tasks
        TASKS=$(az acr task list --registry "$REG_NAME" --resource-group "$REG_RG" -o json 2>/dev/null || echo "[]")
        TASK_COUNT=$(echo "$TASKS" | jq length)
        if [ "$TASK_COUNT" -gt 0 ]; then
            print_warning "    Found $TASK_COUNT ACR task(s)"
            
            # Check for managed identities on tasks
            echo "$TASKS" | jq -c '.[] | select(.identity != null) | {name: .name, identityType: .identity.type}' | while read -r task; do
                TASK_NAME=$(echo "$task" | jq -r '.name')
                IDENTITY_TYPE=$(echo "$task" | jq -r '.identityType')
                print_warning "      Task '$TASK_NAME' has managed identity: $IDENTITY_TYPE"
            done
        fi
        
        # Check if we can list credentials (actual permission test)
        print_info "\n  Testing actual permissions..."
        
        # Test 1: Can we access admin credentials?
        if az acr credential show --name "$REG_NAME" --resource-group "$REG_RG" &>/dev/null; then
            print_finding "CAN ACCESS ADMIN CREDENTIALS!"
            echo -e "${YELLOW}    ✓ You have permission to retrieve admin username/password${NC}"
            {
                echo "SUBSCRIPTION: $SUB_NAME"
                echo "REGISTRY: $REG_NAME"
                echo "RESOURCE GROUP: $REG_RG"
                echo "FINDING: Can access admin credentials"
                echo "TEST: az acr credential show"
                echo "USER: $CURRENT_USER"
                echo "---"
            } >> "$OUTPUT_FILE"
            
            GLOBAL_COUNT=$(cat "$FINDINGS_FILE")
            echo $((GLOBAL_COUNT + 1)) > "$FINDINGS_FILE"
        else
            echo -e "${GRAY}    ✗ Cannot access admin credentials${NC}"
        fi
        
        # Test 2: Can we create tokens?
        TEST_TOKEN_NAME="test-token-$(date +%s)"
        if az acr token create --name "$TEST_TOKEN_NAME" --registry "$REG_NAME" --resource-group "$REG_RG" --repository "*" content/read --only-show-errors &>/dev/null; then
            print_finding "CAN CREATE REPOSITORY TOKENS!"
            echo -e "${YELLOW}    ✓ You have permission to create repository-scoped tokens${NC}"
            
            # Clean up test token
            az acr token delete --name "$TEST_TOKEN_NAME" --registry "$REG_NAME" --resource-group "$REG_RG" --yes &>/dev/null || true
            
            {
                echo "SUBSCRIPTION: $SUB_NAME"
                echo "REGISTRY: $REG_NAME"
                echo "RESOURCE GROUP: $REG_RG"
                echo "FINDING: Can create repository tokens"
                echo "TEST: az acr token create"
                echo "USER: $CURRENT_USER"
                echo "---"
            } >> "$OUTPUT_FILE"
            
            GLOBAL_COUNT=$(cat "$FINDINGS_FILE")
            echo $((GLOBAL_COUNT + 1)) > "$FINDINGS_FILE"
        else
            echo -e "${GRAY}    ✗ Cannot create repository tokens${NC}"
        fi
        
        # Test 3: Can we create tasks?
        TEST_TASK_NAME="test-task-$(date +%s)"
        if az acr task create --name "$TEST_TASK_NAME" --registry "$REG_NAME" --resource-group "$REG_RG" --context /dev/null --cmd hello-world --only-show-errors &>/dev/null; then
            print_finding "CAN CREATE ACR TASKS!"
            echo -e "${YELLOW}    ✓ You have permission to create ACR tasks${NC}"
            echo -e "${YELLOW}    ✓ Tasks can be created with managed identities for privilege escalation${NC}"
            
            # Clean up test task
            az acr task delete --name "$TEST_TASK_NAME" --registry "$REG_NAME" --resource-group "$REG_RG" --yes &>/dev/null || true
            
            {
                echo "SUBSCRIPTION: $SUB_NAME"
                echo "REGISTRY: $REG_NAME"
                echo "RESOURCE GROUP: $REG_RG"
                echo "FINDING: Can create ACR tasks"
                echo "TEST: az acr task create"
                echo "USER: $CURRENT_USER"
                echo "IMPACT: Can create tasks with managed identity for privilege escalation"
                echo "---"
            } >> "$OUTPUT_FILE"
            
            GLOBAL_COUNT=$(cat "$FINDINGS_FILE")
            echo $((GLOBAL_COUNT + 1)) > "$FINDINGS_FILE"
        else
            echo -e "${GRAY}    ✗ Cannot create ACR tasks${NC}"
        fi
        
        # Test 4: Can we manage tokens?
        if az acr token list --registry "$REG_NAME" --resource-group "$REG_RG" &>/dev/null; then
            print_warning "    ✓ Can list/manage repository tokens"
        fi
        
        # Test 5: Can we update registry settings?
        if az acr update --name "$REG_NAME" --resource-group "$REG_RG" --tags "test=test" &>/dev/null; then
            print_finding "CAN MODIFY REGISTRY SETTINGS!"
            echo -e "${YELLOW}    ✓ You have permission to modify registry configuration${NC}"
            echo -e "${YELLOW}    ✓ Could enable admin account if currently disabled${NC}"
            
            {
                echo "SUBSCRIPTION: $SUB_NAME"
                echo "REGISTRY: $REG_NAME"
                echo "RESOURCE GROUP: $REG_RG"
                echo "FINDING: Can modify registry settings"
                echo "TEST: az acr update"
                echo "USER: $CURRENT_USER"
                echo "IMPACT: Can enable admin account, modify security settings"
                echo "---"
            } >> "$OUTPUT_FILE"
            
            GLOBAL_COUNT=$(cat "$FINDINGS_FILE")
            echo $((GLOBAL_COUNT + 1)) > "$FINDINGS_FILE"
        else
            echo -e "${GRAY}    ✗ Cannot modify registry settings${NC}"
        fi
        
        # Check webhooks
        WEBHOOKS=$(az acr webhook list --registry "$REG_NAME" --resource-group "$REG_RG" --query "length(@)" -o tsv 2>/dev/null || echo "0")
        if [ "$WEBHOOKS" != "0" ]; then
            print_warning "    Found $WEBHOOKS webhook(s) configured"
        fi
    done
done

# Summary
print_header "\n\n=== SUMMARY ==="

TOTAL_FINDINGS=$(cat "$FINDINGS_FILE" 2>/dev/null || echo "0")
rm -f "$FINDINGS_FILE"

if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
    print_warning "Total high-risk permissions/findings: $TOTAL_FINDINGS"
    print_success "Results saved to: $OUTPUT_FILE"
    echo ""
    print_info "Key findings breakdown:"
    
    # Count different types of findings
    CRED_ACCESS=$(grep -c "Can access admin credentials" "$OUTPUT_FILE" 2>/dev/null || echo "0")
    TOKEN_CREATE=$(grep -c "Can create repository tokens" "$OUTPUT_FILE" 2>/dev/null || echo "0")
    TASK_CREATE=$(grep -c "Can create ACR tasks" "$OUTPUT_FILE" 2>/dev/null || echo "0")
    REGISTRY_MODIFY=$(grep -c "Can modify registry settings" "$OUTPUT_FILE" 2>/dev/null || echo "0")
    
    [ "$CRED_ACCESS" -gt 0 ] && echo -e "${RED}  - Registries with admin credential access: $CRED_ACCESS${NC}"
    [ "$TOKEN_CREATE" -gt 0 ] && echo -e "${RED}  - Registries where you can create tokens: $TOKEN_CREATE${NC}"
    [ "$TASK_CREATE" -gt 0 ] && echo -e "${RED}  - Registries where you can create tasks: $TASK_CREATE${NC}"
    [ "$REGISTRY_MODIFY" -gt 0 ] && echo -e "${RED}  - Registries you can modify: $REGISTRY_MODIFY${NC}"
    
    echo ""
    print_warning "Review the output file for complete details including:"
    echo "  - Specific principals/users with permissions"
    echo "  - Roles granting the permissions"
    echo "  - Permission scopes"
else
    print_success "No high-risk permissions found across all registries"
    rm -f "$OUTPUT_FILE"
fi

print_info "Completed: $(date)"
