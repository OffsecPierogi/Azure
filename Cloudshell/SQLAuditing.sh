#!/bin/bash

# =============================================================================
# Azure SQL Auditing Status Check Script
# Loops through ALL accessible subscriptions
# Flags server-level auditing, and only flags databases if their server
# does not have auditing enabled
# Run from Azure Cloud Shell (Bash)
# =============================================================================

OUTPUT_FILE="sql_auditing_report_$(date +%Y%m%d_%H%M%S).csv"

echo "=============================================="
echo "Azure SQL Auditing Status Check"
echo "=============================================="
echo ""

# Create CSV header
echo "Asset Name,Asset Type,Auditing Status,Subscription" > "$OUTPUT_FILE"

# Get all accessible subscriptions
echo "Fetching all accessible subscriptions..."
SUBSCRIPTIONS=$(az account list --query "[?state=='Enabled'].{id:id, name:name}" -o json)
SUB_COUNT=$(echo $SUBSCRIPTIONS | jq length)

echo "Found $SUB_COUNT subscription(s)"
echo ""

# Loop through each subscription
echo "$SUBSCRIPTIONS" | jq -c '.[]' | while read sub; do
    SUB_ID=$(echo $sub | jq -r '.id')
    SUB_NAME=$(echo $sub | jq -r '.name')
    
    echo "=============================================="
    echo "SUBSCRIPTION: $SUB_NAME"
    echo "=============================================="
    
    # Set the current subscription
    az account set --subscription "$SUB_ID"
    
    # Get all SQL servers in this subscription
    SERVERS=$(az sql server list --query "[].{name:name, resourceGroup:resourceGroup}" -o json 2>/dev/null)
    
    if [ "$(echo $SERVERS | jq length)" -eq 0 ]; then
        echo "No SQL Servers found."
        continue
    fi
    
    # Loop through each server
    echo "$SERVERS" | jq -c '.[]' | while read server; do
        SERVER_NAME=$(echo $server | jq -r '.name')
        RG=$(echo $server | jq -r '.resourceGroup')
        
        # Check server-level auditing
        SERVER_AUDIT=$(az sql server audit-policy show \
            --resource-group "$RG" \
            --name "$SERVER_NAME" \
            --query "state" -o tsv 2>/dev/null)
        
        if [ "$SERVER_AUDIT" == "Enabled" ]; then
            SERVER_STATUS="Enabled"
            echo "[✓] Server: $SERVER_NAME - Auditing ENABLED"
        else
            SERVER_STATUS="Disabled"
            echo "[✗] Server: $SERVER_NAME - Auditing DISABLED"
        fi
        
        # Write server to CSV
        echo "$SERVER_NAME,SQL Server,$SERVER_STATUS,$SUB_NAME" >> "$OUTPUT_FILE"
        
        # Only check databases if server auditing is DISABLED
        if [ "$SERVER_STATUS" == "Disabled" ]; then
            DATABASES=$(az sql db list \
                --resource-group "$RG" \
                --server "$SERVER_NAME" \
                --query "[?name!='master'].name" -o tsv 2>/dev/null)
            
            for DB_NAME in $DATABASES; do
                DB_AUDIT=$(az sql db audit-policy show \
                    --resource-group "$RG" \
                    --server "$SERVER_NAME" \
                    --name "$DB_NAME" \
                    --query "state" -o tsv 2>/dev/null)
                
                if [ "$DB_AUDIT" == "Enabled" ]; then
                    DB_STATUS="Enabled"
                    echo "    [✓] Database: $DB_NAME - Auditing ENABLED"
                else
                    DB_STATUS="Disabled"
                    echo "    [✗] Database: $DB_NAME - Auditing DISABLED (NOT COVERED)"
                fi
                
                # Write database to CSV
                echo "$DB_NAME,SQL Database,$DB_STATUS,$SUB_NAME" >> "$OUTPUT_FILE"
            done
        fi
    done
    echo ""
done

echo "=============================================="
echo "Scan Complete"
echo "Report exported to: $OUTPUT_FILE"
echo "=============================================="
echo ""
cat "$OUTPUT_FILE"
