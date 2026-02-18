#!/bin/bash

# Azure Key Vault Network Configuration Audit Script
# Checks for publicly accessible Key Vaults across all subscriptions

# Output file
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CSV_FILE="keyvault_accessibility_${TIMESTAMP}.csv"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Azure Key Vault Network Audit"
echo "=========================================="
echo ""

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo -e "${RED}Error: Azure CLI is not installed${NC}"
    exit 1
fi

# Check if logged in
echo "Checking Azure authentication..."
az account show &> /dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Not logged into Azure. Please run 'az login'${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Authenticated to Azure${NC}"
echo ""

# Initialize CSV file
echo "Subscription,Resource Group,Key Vault Name,Location,Accessibility Status,Public Network Access,Default Action,IP Rules,VNet Rules,Private Endpoints" > "$CSV_FILE"

# Get all subscriptions
echo "Fetching subscriptions..."
SUBSCRIPTIONS=$(az account list --query "[].{id:id, name:name}" -o json)

if [ -z "$SUBSCRIPTIONS" ] || [ "$SUBSCRIPTIONS" == "[]" ]; then
    echo -e "${RED}No subscriptions found${NC}"
    exit 1
fi

TOTAL_SUBS=$(echo "$SUBSCRIPTIONS" | jq '. | length')
echo -e "${GREEN}Found $TOTAL_SUBS subscription(s)${NC}"
echo ""

CURRENT_SUB=0
TOTAL_KV=0
PUBLIC_KV=0

# Loop through each subscription
echo "$SUBSCRIPTIONS" | jq -c '.[]' | while read -r sub; do
    CURRENT_SUB=$((CURRENT_SUB + 1))
    SUB_ID=$(echo "$sub" | jq -r '.id')
    SUB_NAME=$(echo "$sub" | jq -r '.name')
    
    echo "----------------------------------------"
    echo "[$CURRENT_SUB/$TOTAL_SUBS] Processing: $SUB_NAME"
    echo "----------------------------------------"
    
    # Set the subscription context
    az account set --subscription "$SUB_ID" 2>/dev/null
    
    # Get all Key Vaults in this subscription
    KEY_VAULTS=$(az keyvault list --query "[].{name:name, resourceGroup:resourceGroup, location:location}" -o json 2>/dev/null)
    
    if [ -z "$KEY_VAULTS" ] || [ "$KEY_VAULTS" == "[]" ]; then
        echo -e "${YELLOW}No Key Vaults found in this subscription${NC}"
        echo ""
        continue
    fi
    
    KV_COUNT=$(echo "$KEY_VAULTS" | jq '. | length')
    echo -e "Found ${GREEN}$KV_COUNT${NC} Key Vault(s)"
    echo ""
    
    # Loop through each Key Vault
    echo "$KEY_VAULTS" | jq -c '.[]' | while read -r kv; do
        TOTAL_KV=$((TOTAL_KV + 1))
        KV_NAME=$(echo "$kv" | jq -r '.name')
        RG_NAME=$(echo "$kv" | jq -r '.resourceGroup')
        LOCATION=$(echo "$kv" | jq -r '.location')
        
        echo "  Checking: $KV_NAME"
        
        # Get detailed network configuration
        KV_DETAILS=$(az keyvault show --name "$KV_NAME" --resource-group "$RG_NAME" -o json 2>/dev/null)
        
        if [ -z "$KV_DETAILS" ]; then
            echo -e "    ${RED}✗ Failed to retrieve details${NC}"
            echo "\"$SUB_NAME\",\"$RG_NAME\",\"$KV_NAME\",\"$LOCATION\",\"ERROR - Unable to retrieve details\",\"Unknown\",\"Unknown\",0,0,\"Unknown\"" >> "$CSV_FILE"
            continue
        fi
        
        # Extract network settings
        PUBLIC_ACCESS=$(echo "$KV_DETAILS" | jq -r '.properties.publicNetworkAccess // "Enabled"')
        DEFAULT_ACTION=$(echo "$KV_DETAILS" | jq -r '.properties.networkAcls.defaultAction // "Allow"')
        IP_RULES=$(echo "$KV_DETAILS" | jq -r '.properties.networkAcls.ipRules // [] | length')
        VNET_RULES=$(echo "$KV_DETAILS" | jq -r '.properties.networkAcls.virtualNetworkRules // [] | length')
        
        # Check for private endpoints
        PRIVATE_ENDPOINTS=$(az network private-endpoint-connection list \
            --name "$KV_NAME" \
            --resource-group "$RG_NAME" \
            --type Microsoft.KeyVault/vaults \
            --query "[].properties.privateLinkServiceConnectionState.status" -o json 2>/dev/null)
        
        if [ -z "$PRIVATE_ENDPOINTS" ] || [ "$PRIVATE_ENDPOINTS" == "[]" ]; then
            PE_COUNT=0
            PE_STATUS="None"
        else
            PE_COUNT=$(echo "$PRIVATE_ENDPOINTS" | jq '. | length')
            PE_STATUS="$PE_COUNT"
        fi
        
        # Determine accessibility status
        ACCESSIBILITY_STATUS=""
        
        if [ "$PUBLIC_ACCESS" == "Enabled" ] && [ "$DEFAULT_ACTION" == "Allow" ]; then
            ACCESSIBILITY_STATUS="PUBLICLY ACCESSIBLE"
            PUBLIC_KV=$((PUBLIC_KV + 1))
            echo -e "    ${RED}✗ PUBLICLY ACCESSIBLE${NC}"
            
        elif [ "$PUBLIC_ACCESS" == "Enabled" ] && [ "$DEFAULT_ACTION" == "Deny" ] && [ "$IP_RULES" -eq 0 ] && [ "$VNET_RULES" -eq 0 ]; then
            ACCESSIBILITY_STATUS="Limited (No allow rules configured)"
            echo -e "    ${YELLOW}⚠ Limited - No allow rules${NC}"
            
        elif [ "$PUBLIC_ACCESS" == "Enabled" ] && [ "$DEFAULT_ACTION" == "Deny" ]; then
            ACCESSIBILITY_STATUS="Limited (Firewall restricted)"
            echo -e "    ${YELLOW}⚠ Limited - Firewall enabled${NC}"
            
        elif [ "$PUBLIC_ACCESS" == "Disabled" ] && [ "$PE_COUNT" -gt 0 ]; then
            ACCESSIBILITY_STATUS="Private Only"
            echo -e "    ${GREEN}✓ Private endpoints only${NC}"
            
        elif [ "$PUBLIC_ACCESS" == "Disabled" ] && [ "$PE_COUNT" -eq 0 ]; then
            ACCESSIBILITY_STATUS="Limited (No private endpoints)"
            echo -e "    ${YELLOW}⚠ Disabled - No private endpoints${NC}"
        else
            ACCESSIBILITY_STATUS="Unknown configuration"
            echo -e "    ${YELLOW}? Unknown${NC}"
        fi
        
        # Write to CSV
        echo "\"$SUB_NAME\",\"$RG_NAME\",\"$KV_NAME\",\"$LOCATION\",\"$ACCESSIBILITY_STATUS\",\"$PUBLIC_ACCESS\",\"$DEFAULT_ACTION\",$IP_RULES,$VNET_RULES,$PE_COUNT" >> "$CSV_FILE"
        
    done
    echo ""
done

echo ""
echo "=========================================="
echo "Audit Complete!"
echo "=========================================="
echo ""
echo "Output file: $CSV_FILE"
echo ""

# Display summary
PUBLIC_COUNT=$(grep -c "PUBLICLY ACCESSIBLE" "$CSV_FILE" 2>/dev/null || echo "0")
if [ "$PUBLIC_COUNT" -gt 0 ]; then
    echo -e "${RED}⚠ WARNING: Found $PUBLIC_COUNT publicly accessible Key Vault(s)!${NC}"
    echo ""
    echo "Publicly accessible Key Vaults:"
    grep "PUBLICLY ACCESSIBLE" "$CSV_FILE" | awk -F',' '{print "  - " $3}'
    echo ""
else
    echo -e "${GREEN}✓ No publicly accessible Key Vaults found${NC}"
    echo ""
fi

TOTAL_COUNT=$(wc -l < "$CSV_FILE")
TOTAL_COUNT=$((TOTAL_COUNT - 1))  # Subtract header row
echo "Total Key Vaults scanned: $TOTAL_COUNT"
echo ""
echo "Done!"
