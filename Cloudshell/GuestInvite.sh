#!/bin/bash

##############################################################################
# Script: detect-azure-guest-settings.sh
# Description: Detects guest invite settings in Azure AD (Microsoft Entra ID)
# Requirements: Azure CLI (az) must be installed and configured
# Permissions: Directory.Read.All or Policy.Read.All
##############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
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

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    print_color "$RED" "Error: Azure CLI (az) is not installed."
    exit 1
fi

# Cloud Shell is already authenticated
print_color "$CYAN" "Using Cloud Shell authentication..."

# Get the current tenant information
TENANT_ID=$(az account show --query tenantId -o tsv)
print_color "$CYAN" "\nTenant ID: $TENANT_ID"

# Prepare output file
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="azure-guest-settings-$TIMESTAMP.txt"

# Start building output
{
    echo "========================================"
    echo "AZURE AD GUEST INVITE SETTINGS REPORT"
    echo "========================================"
    echo ""
    echo "Report Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Tenant ID: $TENANT_ID"
    echo ""
} > "$OUTPUT_FILE"

# Retrieve Authorization Policy
print_color "$CYAN" "\nRetrieving Azure AD Authorization Policy..."

AUTH_POLICY=$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" 2>&1)

if [ $? -ne 0 ]; then
    print_color "$RED" "\nError retrieving authorization policy."
    print_color "$YELLOW" "Make sure you have the required permissions (Policy.Read.All or Directory.Read.All)"
    print_color "$YELLOW" "\nYou may need to run: az login --scope https://graph.microsoft.com/.default"
    exit 1
fi

# Parse the JSON response
GUEST_ROLE_ID=$(echo "$AUTH_POLICY" | jq -r '.guestUserRoleId // "unknown"')
ALLOW_INVITES_FROM=$(echo "$AUTH_POLICY" | jq -r '.allowInvitesFrom // "unknown"')
ALLOW_EMAIL_VERIFIED=$(echo "$AUTH_POLICY" | jq -r '.allowEmailVerifiedUsersToJoinOrganization // false')
ALLOW_SIGNUP=$(echo "$AUTH_POLICY" | jq -r '.allowedToSignUpEmailBasedSubscriptions // false')
BLOCK_MSOL=$(echo "$AUTH_POLICY" | jq -r '.blockMsolPowerShell // false')

# Display Guest Invite Settings
print_header "GUEST INVITE SETTINGS"

{
    echo "========================================"
    echo "GUEST INVITE SETTINGS"
    echo "========================================"
    echo ""
} >> "$OUTPUT_FILE"

print_color "$YELLOW" "\nGuest User Access Restrictions:"
echo "Guest User Access Restrictions:" >> "$OUTPUT_FILE"

case "$GUEST_ROLE_ID" in
    "a0b1b346-4d3e-4e8b-98f8-753987be4970")
        print_color "$WHITE" "  Level: Same as member users (most permissive)"
        echo "  Level: Same as member users (most permissive)" >> "$OUTPUT_FILE"
        RESTRICTION_LEVEL="Least Restrictive"
        ;;
    "10dae51f-b6af-4016-8d66-8c2a99b929b3")
        print_color "$WHITE" "  Level: Limited access (default)"
        echo "  Level: Limited access (default)" >> "$OUTPUT_FILE"
        RESTRICTION_LEVEL="Moderately Restrictive"
        ;;
    "2af84b1e-32c8-42b7-82bc-daa82404023b")
        print_color "$WHITE" "  Level: Restricted access (most restrictive)"
        echo "  Level: Restricted access (most restrictive)" >> "$OUTPUT_FILE"
        RESTRICTION_LEVEL="Most Restrictive"
        ;;
    *)
        print_color "$WHITE" "  Level: Custom ($GUEST_ROLE_ID)"
        echo "  Level: Custom ($GUEST_ROLE_ID)" >> "$OUTPUT_FILE"
        RESTRICTION_LEVEL="Custom"
        ;;
esac
echo "" >> "$OUTPUT_FILE"

print_color "$YELLOW" "\nWho Can Invite Guests:"
print_color "$WHITE" "  Allow Invitations From: $ALLOW_INVITES_FROM"

{
    echo "Who Can Invite Guests:"
    echo "  Allow Invitations From: $ALLOW_INVITES_FROM"
} >> "$OUTPUT_FILE"

case "$ALLOW_INVITES_FROM" in
    "everyone")
        print_color "$GRAY" "    → All users in the organization can invite guests"
        echo "    → All users in the organization can invite guests" >> "$OUTPUT_FILE"
        ;;
    "adminsAndGuestInviters")
        print_color "$GRAY" "    → Only admins and users with Guest Inviter role can invite"
        echo "    → Only admins and users with Guest Inviter role can invite" >> "$OUTPUT_FILE"
        ;;
    "adminsGuestInvitersAndAllMembers")
        print_color "$GRAY" "    → Admins, Guest Inviters, and all members can invite (guests cannot)"
        echo "    → Admins, Guest Inviters, and all members can invite (guests cannot)" >> "$OUTPUT_FILE"
        ;;
    "none")
        print_color "$GRAY" "    → No one can invite guests"
        echo "    → No one can invite guests" >> "$OUTPUT_FILE"
        ;;
esac
echo "" >> "$OUTPUT_FILE"

print_color "$YELLOW" "\nGuest User Permissions:"
print_color "$WHITE" "  Block MSOL PowerShell: $BLOCK_MSOL"

{
    echo "Guest User Permissions:"
    echo "  Block MSOL PowerShell: $BLOCK_MSOL"
    echo ""
} >> "$OUTPUT_FILE"

print_color "$YELLOW" "\nExternal Collaboration Settings:"
print_color "$WHITE" "  Allowed To Sign Up Email Based Subscriptions: $ALLOW_SIGNUP"
print_color "$WHITE" "  Allowed Email Verified Users To Join Organization: $ALLOW_EMAIL_VERIFIED"

{
    echo "External Collaboration Settings:"
    echo "  Allowed To Sign Up Email Based Subscriptions: $ALLOW_SIGNUP"
    echo "  Allowed Email Verified Users To Join Organization: $ALLOW_EMAIL_VERIFIED"
    echo ""
} >> "$OUTPUT_FILE"

# Display Summary
print_header "SUMMARY"

{
    echo "========================================"
    echo "SUMMARY"
    echo "========================================"
    echo ""
    echo "Guest Access Level: $RESTRICTION_LEVEL"
    echo "Invite Policy: $ALLOW_INVITES_FROM"
    echo ""
} >> "$OUTPUT_FILE"

print_color "$CYAN" "\nGuest Access Level: $RESTRICTION_LEVEL"
print_color "$CYAN" "Invite Policy: $ALLOW_INVITES_FROM"

# Security warnings - only show if policy is 'everyone'
if [ "$ALLOW_INVITES_FROM" = "everyone" ]; then
    print_color "$RED" "\n⚠️  WARNING: All users can invite guests - consider restricting this"
    echo "⚠️  WARNING: All users can invite guests - consider restricting this" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
fi

if [ "$ALLOW_EMAIL_VERIFIED" = "true" ]; then
    print_color "$RED" "⚠️  WARNING: Email-verified users can join organization - consider reviewing this setting"
    echo "⚠️  WARNING: Email-verified users can join organization - consider reviewing this setting" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
fi

print_color "$GREEN" "\nReport saved to: $OUTPUT_FILE"
print_color "$GREEN" "Script completed successfully!"
