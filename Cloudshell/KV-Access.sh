#!/bin/bash

##############################################################################
# Script: check-keyvault-access.sh
# Description: Checks if the current user has access to any Azure Key Vaults
#              Supports single or multiple subscriptions
# Requirements: Azure CLI (az) - already available in Cloud Shell
# Permissions: Reader access to subscriptions and Key Vaults
#
# Usage:
#   ./check-keyvault-access.sh                    # Interactive mode
#   ./check-keyvault-access.sh -s "sub1,sub2"     # Specific subscriptions
#   ./check-keyvault-access.sh -a                 # All subscriptions
##############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Function to print section headers
print_header() {
    print_color "$GREEN" "\n========================================"
    print_color "$GREEN" "$1"
    print_color "$GREEN" "========================================"
}

# Parse command line arguments
ALL_SUBS=false
SUBSCRIPTION_IDS=""

while getopts "as:" opt; do
    case $opt in
        a)
            ALL_SUBS=true
            ;;
        s)
            SUBSCRIPTION_IDS="$OPTARG"
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            echo "Usage: $0 [-a] [-s subscription_ids]"
            echo "  -a: Check all subscriptions"
            echo "  -s: Comma-separated subscription IDs"
            exit 1
            ;;
    esac
done

print_color "$CYAN" "Azure Key Vault Access Checker"
print_color "$CYAN" "================================\n"

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    print_color "$RED" "Error: Azure CLI (az) is not installed."
    exit 1
fi

# Cloud Shell is already authenticated
print_color "$YELLOW" "Getting current user context..."

# Get current user context
CURRENT_USER=$(az account show --query user.name -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

print_color "$GREEN" "User: $CURRENT_USER"
print_color "$GREEN" "Tenant ID: $TENANT_ID\n"

# Get all available subscriptions
print_color "$YELLOW" "Retrieving available subscriptions..."
ALL_SUBS_JSON=$(az account list --query "[?state=='Enabled'].{id:id, name:name}" -o json)

if [ $? -ne 0 ]; then
    print_color "$RED" "Error: Failed to retrieve subscriptions"
    exit 1
fi

TOTAL_AVAILABLE=$(echo "$ALL_SUBS_JSON" | jq '. | length')

if [ "$TOTAL_AVAILABLE" -eq 0 ]; then
    print_color "$RED" "No enabled subscriptions found."
    exit 1
fi

# Determine which subscriptions to check
SUBS_TO_CHECK="[]"

if [ "$ALL_SUBS" = true ]; then
    print_color "$GREEN" "Checking ALL subscriptions ($TOTAL_AVAILABLE total)\n"
    SUBS_TO_CHECK="$ALL_SUBS_JSON"
elif [ -n "$SUBSCRIPTION_IDS" ]; then
    # Parse comma-separated IDs
    IFS=',' read -ra SUB_ARRAY <<< "$SUBSCRIPTION_IDS"
    SUBS_TO_CHECK="[]"
    
    for sub_id in "${SUB_ARRAY[@]}"; do
        sub_id=$(echo "$sub_id" | xargs) # trim whitespace
        SUB_INFO=$(echo "$ALL_SUBS_JSON" | jq ".[] | select(.id == \"$sub_id\")")
        
        if [ -n "$SUB_INFO" ]; then
            SUBS_TO_CHECK=$(echo "$SUBS_TO_CHECK" | jq ". += [$SUB_INFO]")
        else
            print_color "$YELLOW" "Warning: Subscription ID '$sub_id' not found or not accessible"
        fi
    done
    
    SUB_COUNT=$(echo "$SUBS_TO_CHECK" | jq '. | length')
    if [ "$SUB_COUNT" -eq 0 ]; then
        print_color "$RED" "No valid subscriptions found to check."
        exit 1
    fi
else
    # Interactive mode
    print_color "$CYAN" "Available Subscriptions:"
    
    for i in $(seq 0 $((TOTAL_AVAILABLE - 1))); do
        SUB_NAME=$(echo "$ALL_SUBS_JSON" | jq -r ".[$i].name")
        SUB_ID=$(echo "$ALL_SUBS_JSON" | jq -r ".[$i].id")
        print_color "$WHITE" "  [$((i + 1))] $SUB_NAME ($SUB_ID)"
    done
    print_color "$WHITE" "  [A] All subscriptions"
    
    echo -ne "\n${CYAN}Enter subscription number(s) separated by commas (e.g., 1,3,5) or 'A' for all: ${NC}"
    read -r SELECTION
    
    if [[ "$SELECTION" =~ ^[Aa]$ ]]; then
        SUBS_TO_CHECK="$ALL_SUBS_JSON"
        print_color "$GREEN" "Selected: All subscriptions\n"
    else
        IFS=',' read -ra INDICES <<< "$SELECTION"
        SUBS_TO_CHECK="[]"
        
        for index in "${INDICES[@]}"; do
            index=$(echo "$index" | xargs) # trim whitespace
            
            if [[ "$index" =~ ^[0-9]+$ ]]; then
                idx=$((index - 1))
                
                if [ "$idx" -ge 0 ] && [ "$idx" -lt "$TOTAL_AVAILABLE" ]; then
                    SUB_INFO=$(echo "$ALL_SUBS_JSON" | jq ".[$idx]")
                    SUBS_TO_CHECK=$(echo "$SUBS_TO_CHECK" | jq ". += [$SUB_INFO]")
                else
                    print_color "$YELLOW" "Warning: Invalid selection '$index' - skipping"
                fi
            fi
        done
        
        SUB_COUNT=$(echo "$SUBS_TO_CHECK" | jq '. | length')
        if [ "$SUB_COUNT" -eq 0 ]; then
            print_color "$RED" "No valid subscriptions selected."
            exit 1
        fi
        
        print_color "$GREEN" "Selected $SUB_COUNT subscription(s)\n"
    fi
fi

# Show subscriptions to check
SUBS_COUNT=$(echo "$SUBS_TO_CHECK" | jq '. | length')
print_color "$CYAN" "Subscriptions to check:"
for i in $(seq 0 $((SUBS_COUNT - 1))); do
    SUB_NAME=$(echo "$SUBS_TO_CHECK" | jq -r ".[$i].name")
    SUB_ID=$(echo "$SUBS_TO_CHECK" | jq -r ".[$i].id")
    print_color "$GRAY" "  - $SUB_NAME ($SUB_ID)"
done
echo ""

# Prepare output file
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="keyvault-access-report-$TIMESTAMP.txt"

# Start building output
{
    echo "========================================"
    echo "AZURE KEY VAULT ACCESS REPORT"
    echo "========================================"
    echo ""
    echo "Report Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "User: $CURRENT_USER"
    echo "Tenant ID: $TENANT_ID"
    echo "Subscriptions Checked: $SUBS_COUNT"
    echo ""
} > "$OUTPUT_FILE"

# Track overall accessible vaults
TOTAL_ACCESSIBLE=0
TOTAL_INACCESSIBLE=0
TOTAL_VAULTS=0

# Process each subscription
for i in $(seq 0 $((SUBS_COUNT - 1))); do
    SUB_NAME=$(echo "$SUBS_TO_CHECK" | jq -r ".[$i].name")
    SUB_ID=$(echo "$SUBS_TO_CHECK" | jq -r ".[$i].id")
    
    print_color "$MAGENTA" "\n========================================"
    print_color "$MAGENTA" "Subscription: $SUB_NAME"
    print_color "$MAGENTA" "========================================"
    
    {
        echo "========================================"
        echo "Subscription: $SUB_NAME"
        echo "Subscription ID: $SUB_ID"
        echo "========================================"
        echo ""
    } >> "$OUTPUT_FILE"
    
    # Set active subscription
    az account set --subscription "$SUB_ID" &>/dev/null
    
    # Get all Key Vaults in this subscription
    print_color "$YELLOW" "Scanning for Key Vaults..."
    
    VAULTS_JSON=$(az keyvault list --query "[].{name:name, resourceGroup:resourceGroup, location:location}" -o json 2>&1)
    
    if [ $? -ne 0 ]; then
        print_color "$RED" "Error: Failed to list Key Vaults in this subscription"
        echo "Error: Failed to list Key Vaults in this subscription" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        continue
    fi
    
    VAULT_COUNT=$(echo "$VAULTS_JSON" | jq '. | length')
    
    if [ "$VAULT_COUNT" -eq 0 ]; then
        print_color "$YELLOW" "No Key Vaults found in this subscription.\n"
        echo "No Key Vaults found in this subscription." >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        continue
    fi
    
    print_color "$GREEN" "Found $VAULT_COUNT Key Vault(s)\n"
    echo "Total Key Vaults Found: $VAULT_COUNT" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    TOTAL_VAULTS=$((TOTAL_VAULTS + VAULT_COUNT))
    
    # Track accessible vaults in this subscription
    SUB_ACCESSIBLE=0
    SUB_INACCESSIBLE=0
    
    # Parse each vault
    for j in $(seq 0 $((VAULT_COUNT - 1))); do
        VAULT_NAME=$(echo "$VAULTS_JSON" | jq -r ".[$j].name")
        RESOURCE_GROUP=$(echo "$VAULTS_JSON" | jq -r ".[$j].resourceGroup")
        LOCATION=$(echo "$VAULTS_JSON" | jq -r ".[$j].location")
        
        print_color "$CYAN" "Checking: $VAULT_NAME"
        
        {
            echo "----------------------------------------"
            echo "Key Vault: $VAULT_NAME"
            echo "Resource Group: $RESOURCE_GROUP"
            echo "Location: $LOCATION"
        } >> "$OUTPUT_FILE"
        
        # Try to list secrets to check access
        SECRETS_RESULT=$(az keyvault secret list --vault-name "$VAULT_NAME" 2>&1)
        EXIT_CODE=$?
        
        if [ $EXIT_CODE -eq 0 ]; then
            SECRET_COUNT=$(echo "$SECRETS_RESULT" | jq '. | length' 2>/dev/null || echo "0")
            
            print_color "$GREEN" "  ✓ ACCESS GRANTED"
            print_color "$GRAY" "    - Can list secrets: Yes"
            print_color "$GRAY" "    - Secret count: $SECRET_COUNT\n"
            
            {
                echo "Access Status: ✓ GRANTED"
                echo "  - Can list secrets: Yes"
                echo "  - Secret count: $SECRET_COUNT"
            } >> "$OUTPUT_FILE"
            
            # Check for additional permissions
            PERMISSIONS=""
            
            if az keyvault key list --vault-name "$VAULT_NAME" &>/dev/null; then
                PERMISSIONS="List Keys"
            fi
            
            if az keyvault certificate list --vault-name "$VAULT_NAME" &>/dev/null; then
                if [ -n "$PERMISSIONS" ]; then
                    PERMISSIONS="$PERMISSIONS, List Certificates"
                else
                    PERMISSIONS="List Certificates"
                fi
            fi
            
            if [ -n "$PERMISSIONS" ]; then
                echo "  - Additional Permissions: $PERMISSIONS" >> "$OUTPUT_FILE"
            fi
            
            ((SUB_ACCESSIBLE++))
            ((TOTAL_ACCESSIBLE++))
        else
            print_color "$RED" "  ✗ ACCESS DENIED"
            ERROR_MSG=$(echo "$SECRETS_RESULT" | head -n 1)
            print_color "$GRAY" "    - Error: $ERROR_MSG\n"
            
            {
                echo "Access Status: ✗ DENIED"
                echo "  - Error: $ERROR_MSG"
            } >> "$OUTPUT_FILE"
            
            ((SUB_INACCESSIBLE++))
            ((TOTAL_INACCESSIBLE++))
        fi
        
        echo "" >> "$OUTPUT_FILE"
    done
    
    # Subscription summary
    print_color "$YELLOW" "Subscription Summary:"
    print_color "$WHITE" "  Total Key Vaults: $VAULT_COUNT"
    print_color "$GREEN" "  Accessible: $SUB_ACCESSIBLE"
    print_color "$RED" "  Inaccessible: $SUB_INACCESSIBLE"
    
    {
        echo "Subscription Summary:"
        echo "  Total Key Vaults: $VAULT_COUNT"
        echo "  Accessible: $SUB_ACCESSIBLE"
        echo "  Inaccessible: $SUB_INACCESSIBLE"
        echo ""
    } >> "$OUTPUT_FILE"
done

# Overall Summary
print_header "OVERALL SUMMARY"

print_color "$WHITE" "Subscriptions Checked: $SUBS_COUNT"
print_color "$WHITE" "Total Key Vaults: $TOTAL_VAULTS"
print_color "$GREEN" "Accessible: $TOTAL_ACCESSIBLE"
print_color "$RED" "Inaccessible: $TOTAL_INACCESSIBLE"

{
    echo "========================================"
    echo "OVERALL SUMMARY"
    echo "========================================"
    echo "Subscriptions Checked: $SUBS_COUNT"
    echo "Total Key Vaults: $TOTAL_VAULTS"
    echo "Accessible: $TOTAL_ACCESSIBLE"
    echo "Inaccessible: $TOTAL_INACCESSIBLE"
    echo ""
} >> "$OUTPUT_FILE"

if [ "$TOTAL_ACCESSIBLE" -eq 0 ]; then
    print_color "$YELLOW" "\n⚠️  WARNING: You do not have access to any Key Vaults"
    print_color "$GRAY" "No output file created (no accessible vaults found)\n"
    rm -f "$OUTPUT_FILE"
else
    print_color "$GREEN" "\nReport saved to: $OUTPUT_FILE"
fi

print_color "$GREEN" "Script completed successfully!"
