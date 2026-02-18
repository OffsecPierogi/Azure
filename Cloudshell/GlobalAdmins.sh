#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
#
# Extracts all members of the Global Administrator role from
# Microsoft Entra ID and provides a count.
#
# Run in Azure Cloud Shell (Bash). Requires: Azure CLI
# Usage: chmod +x global_admins.sh && ./global_admins.sh
# ════════════════════════════════════════════════════════════════════

set -uo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; MAGENTA='\033[0;35m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${CYAN}  [INFO]  $*${NC}"; }
ok()      { echo -e "${GREEN}  [OK]    $*${NC}"; }
warn()    { echo -e "${YELLOW}  [WARN]  $*${NC}"; }
section() { echo -e "\n${MAGENTA}$*${NC}"; }
err()     { echo -e "${RED}  [ERROR] $*${NC}"; }

# Global Administrator role template ID — fixed across all tenants
GLOBAL_ADMIN_TEMPLATE_ID="62e90394-69f5-4237-9190-012177145e10"

# ── Login check ────────────────────────────────────────────────────
if ! az account show &>/dev/null; then
    info "No active session — running az login..."
    az login
fi

# ── Get tenant ID ──────────────────────────────────────────────────
TENANT_ID=$(az account show --query tenantId --output tsv 2>/dev/null)
TENANT_NAME=$(az rest \
    --method GET \
    --url "https://graph.microsoft.com/v1.0/organization" \
    --query "value[0].displayName" \
    --output tsv 2>/dev/null || echo "Unknown Tenant")

info "Tenant : $TENANT_NAME  ($TENANT_ID)"

# ── Find the activated Global Administrator role ───────────────────
info "Looking up Global Administrator role..."

ROLE_ID=$(az rest \
    --method GET \
    --url "https://graph.microsoft.com/v1.0/directoryRoles" \
    --query "value[?roleTemplateId=='${GLOBAL_ADMIN_TEMPLATE_ID}'].id | [0]" \
    --output tsv 2>/dev/null || true)

# If role not activated yet, activate it via the template
if [[ -z "$ROLE_ID" || "$ROLE_ID" == "None" ]]; then
    info "Role not yet activated — activating via template..."
    az rest \
        --method POST \
        --url "https://graph.microsoft.com/v1.0/directoryRoles" \
        --body "{\"roleTemplateId\": \"${GLOBAL_ADMIN_TEMPLATE_ID}\"}" \
        --headers "Content-Type=application/json" &>/dev/null || true

    ROLE_ID=$(az rest \
        --method GET \
        --url "https://graph.microsoft.com/v1.0/directoryRoles" \
        --query "value[?roleTemplateId=='${GLOBAL_ADMIN_TEMPLATE_ID}'].id | [0]" \
        --output tsv 2>/dev/null || true)
fi

if [[ -z "$ROLE_ID" || "$ROLE_ID" == "None" ]]; then
    err "Could not retrieve Global Administrator role. Check your permissions."
    exit 1
fi

ok "Found role  |  Role ID: $ROLE_ID"

# ── Get all members ────────────────────────────────────────────────
info "Fetching role members..."

MEMBERS_JSON=$(az rest \
    --method GET \
    --url "https://graph.microsoft.com/v1.0/directoryRoles/${ROLE_ID}/members" \
    --query "value[].{id:id, displayName:displayName, upn:userPrincipalName, type:\"@odata.type\", enabled:accountEnabled}" \
    --output json 2>/dev/null || echo "[]")

MEMBER_COUNT=$(echo "$MEMBERS_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")

if [[ "$MEMBER_COUNT" -eq 0 ]]; then
    warn "No members found in the Global Administrator role."
    exit 0
fi

# ── Print results ──────────────────────────────────────────────────
section "════════════════════════════════════════════════════"
echo -e "  ${MAGENTA}GLOBAL ADMINISTRATOR MEMBERS${NC}"
section "════════════════════════════════════════════════════"

CSV_FILE="./GlobalAdmins_$(date +"%Y%m%d_%H%M%S").csv"
printf 'No.,Display Name,UPN / App ID,Object Type,Account Enabled,Object ID\n' > "$CSV_FILE"

echo "$MEMBERS_JSON" | python3 -c "
import sys, json

members = json.load(sys.stdin)
for i, m in enumerate(members, 1):
    raw_type    = m.get('type', 'unknown')
    obj_type    = raw_type.replace('#microsoft.graph.', '')
    display     = m.get('displayName') or 'N/A'
    upn         = m.get('upn')         or 'N/A'
    enabled     = m.get('enabled')
    enabled_str = str(enabled) if enabled is not None else 'N/A'
    obj_id      = m.get('id', 'N/A')

    # Print to terminal
    print(f'  {i:>3}. {display:<40} {upn:<50} Type: {obj_type:<20} Enabled: {enabled_str}')

    # Write CSV row
    print(f'\"{i}\",\"{display}\",\"{upn}\",\"{obj_type}\",\"{enabled_str}\",\"{obj_id}\"', file=open('$CSV_FILE', 'a'))
"

# ── Summary ────────────────────────────────────────────────────────
section "════════════════════════════════════════════════════"
echo -e "  ${GREEN}Total Global Administrators : $MEMBER_COUNT${NC}"
section "════════════════════════════════════════════════════"
ok "Results saved to: $CSV_FILE"
