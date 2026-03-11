#!/bin/bash
# =============================================================================
# Find Azure AD / Entra ID Groups Joinable by Users
# Outputs results to CSV, then prompts to join selected groups
# Run from Azure Cloud Shell (Bash)
# =============================================================================

OUTPUT_FILE="$HOME/joinable-groups-$(date +%Y%m%d-%H%M%S).csv"
GRAPH="https://graph.microsoft.com/v1.0"

echo "============================================="
echo " Scanning for User-Joinable Groups"
echo "============================================="
echo ""

# Acquire token
TOKEN=$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
if [ -z "$TOKEN" ]; then
    echo "ERROR: Could not acquire access token. Run: az login"
    exit 1
fi

AUTH_HEADER="Authorization: Bearer $TOKEN"

# Get current user ID for join operations
MY_ID=$(curl -s -H "$AUTH_HEADER" "${GRAPH}/me?\$select=id" | jq -r '.id // empty')
if [ -z "$MY_ID" ]; then
    echo "ERROR: Could not retrieve your user ID."
    exit 1
fi
echo "Logged in as user ID: $MY_ID"
echo ""

# CSV header
echo '"Id","DisplayName","Description","SecurityEnabled","MailEnabled","GroupType","MemberCount","AssignedRoles"' > "$OUTPUT_FILE"

# Helper: escape a field for CSV
csv_escape() {
    local val
    val=$(printf '%s' "$1" | tr '\n' ' ' | tr '\r' ' ')
    val="${val//\"/\"\"}"
    printf '"%s"' "$val"
}

echo "Fetching groups..."
echo ""

# Store group info for the join menu later
declare -a GROUP_IDS
declare -a GROUP_NAMES

NEXT_LINK="${GRAPH}/groups?\$select=id,displayName,description,groupTypes,visibility,mailEnabled,securityEnabled&\$top=999"
COUNT=0

while [ -n "$NEXT_LINK" ]; do
    RESPONSE=$(curl -s \
        -H "$AUTH_HEADER" \
        -H "Content-Type: application/json" \
        -H "ConsistencyLevel: eventual" \
        "$NEXT_LINK")

    # Save filtered groups to a temp file to avoid subshell/pipe issues
    TMPFILE=$(mktemp)
    echo "$RESPONSE" | jq -c '
        [.value[]? |
         (if (.groupTypes // [] | index("DynamicMembership")) then true else false end) as $isDynamic |
         (.visibility // "Unknown") as $vis |
         select($isDynamic == false and $vis == "Public")
        ] // []
    ' > "$TMPFILE"

    GROUP_COUNT=$(jq 'length' "$TMPFILE")

    for (( i=0; i<GROUP_COUNT; i++ )); do
        GID=$(jq -r ".[$i].id" "$TMPFILE")
        DNAME=$(jq -r ".[$i].displayName // \"N/A\"" "$TMPFILE")
        DESC=$(jq -r ".[$i].description // \"\"" "$TMPFILE")
        SEC=$(jq -r ".[$i].securityEnabled" "$TMPFILE")
        MAIL=$(jq -r ".[$i].mailEnabled" "$TMPFILE")
        IS_UNIFIED=$(jq -r "if (.[$i].groupTypes // [] | index(\"Unified\")) then \"yes\" else \"no\" end" "$TMPFILE")

        # Determine group type label
        if [ "$IS_UNIFIED" = "yes" ]; then
            GTYPE="Microsoft 365"
        elif [ "$SEC" = "true" ] && [ "$MAIL" = "true" ]; then
            GTYPE="Mail-enabled Security"
        elif [ "$SEC" = "true" ]; then
            GTYPE="Security"
        else
            GTYPE="Distribution"
        fi

        echo "  Processing: $DNAME"

        # --- Member count (isolated call) ---
        MCOUNT=$(curl -s \
            -H "$AUTH_HEADER" \
            -H "ConsistencyLevel: eventual" \
            "${GRAPH}/groups/${GID}/members/\$count")
        if ! [[ "$MCOUNT" =~ ^[0-9]+$ ]]; then
            MCOUNT="0"
        fi

        # --- Assigned directory roles (isolated call) ---
        ROLES_RAW=$(curl -s \
            -H "$AUTH_HEADER" \
            -H "Content-Type: application/json" \
            "${GRAPH}/groups/${GID}/transitiveMemberOf/microsoft.graph.directoryRole?\$select=displayName")
        ROLES=$(echo "$ROLES_RAW" | jq -r '[.value[]?.displayName // empty] | if length == 0 then "None" else join("; ") end' 2>/dev/null)
        [ -z "$ROLES" ] && ROLES="None"

        # Write CSV row
        echo "$(csv_escape "$GID"),$(csv_escape "$DNAME"),$(csv_escape "$DESC"),$(csv_escape "$SEC"),$(csv_escape "$MAIL"),$(csv_escape "$GTYPE"),$(csv_escape "$MCOUNT"),$(csv_escape "$ROLES")" >> "$OUTPUT_FILE"

        # Store for join menu
        GROUP_IDS+=("$GID")
        GROUP_NAMES+=("$DNAME")

        COUNT=$((COUNT + 1))
    done

    rm -f "$TMPFILE"

    NEXT_LINK=$(echo "$RESPONSE" | jq -r '.["@odata.nextLink"] // empty')
done

echo ""
echo "============================================="
echo " Scan Complete"
echo "============================================="
echo "  Joinable groups found: $COUNT"
echo "  CSV exported to: $OUTPUT_FILE"
echo "============================================="
echo ""

# =============================================================================
# Interactive: Join groups
# =============================================================================

if [ "$COUNT" -eq 0 ]; then
    echo "No joinable groups to display."
    exit 0
fi

echo "============================================="
echo " Available Groups to Join"
echo "============================================="
echo ""
for (( j=0; j<COUNT; j++ )); do
    echo "  $((j+1))) ${GROUP_NAMES[$j]}"
done
echo ""
echo "  0) Skip - do not join any groups"
echo ""

while true; do
    read -rp "Enter group numbers to join (comma-separated, e.g. 1,3 or 0 to skip): " SELECTION

    if [ "$SELECTION" = "0" ]; then
        echo "Skipping. No groups joined."
        break
    fi

    # Parse comma-separated input
    IFS=',' read -ra PICKS <<< "$SELECTION"
    VALID=true

    for PICK in "${PICKS[@]}"; do
        PICK=$(echo "$PICK" | tr -d ' ')
        if ! [[ "$PICK" =~ ^[0-9]+$ ]] || [ "$PICK" -lt 1 ] || [ "$PICK" -gt "$COUNT" ]; then
            echo "  Invalid selection: $PICK (must be 1-$COUNT)"
            VALID=false
            break
        fi
    done

    if [ "$VALID" = false ]; then
        continue
    fi

    echo ""
    for PICK in "${PICKS[@]}"; do
        PICK=$(echo "$PICK" | tr -d ' ')
        IDX=$((PICK - 1))
        JOIN_GID="${GROUP_IDS[$IDX]}"
        JOIN_NAME="${GROUP_NAMES[$IDX]}"

        echo -n "  Joining '$JOIN_NAME'... "

        JOIN_BODY="{\"@odata.id\":\"${GRAPH}/directoryObjects/${MY_ID}\"}"
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -H "$AUTH_HEADER" \
            -H "Content-Type: application/json" \
            -d "$JOIN_BODY" \
            "${GRAPH}/groups/${JOIN_GID}/members/\$ref")

        if [ "$HTTP_CODE" = "204" ]; then
            echo "SUCCESS"
        elif [ "$HTTP_CODE" = "400" ]; then
            echo "ALREADY A MEMBER"
        else
            echo "FAILED (HTTP $HTTP_CODE)"
        fi
    done

    echo ""
    echo "Done."
    break
done
