#!/bin/bash

echo ""
echo "======================================"
echo " Entra ID User Settings Report"
echo "======================================"

POLICY=$(az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy")

SETTINGS=$(az rest --method GET \
  --uri "https://graph.microsoft.com/beta/settings")

echo ""
echo "--- Default User Role Permissions ---"
echo "Users can register applications          : $(echo $POLICY | jq -r '.defaultUserRolePermissions.allowedToCreateApps')"
echo "Restrict non-admins from creating tenants: $(echo $POLICY | jq -r '.defaultUserRolePermissions.allowedToCreateTenants')"
echo "Users can create security groups         : $(echo $POLICY | jq -r '.defaultUserRolePermissions.allowedToCreateSecurityGroups')"

echo ""
echo "--- Guest User Access ---"
GUEST_ROLE=$(echo $POLICY | jq -r '.guestUserRoleId')
case $GUEST_ROLE in
  "a0b1b346-4d3e-4e8b-98f8-753987be4970")
    echo "Guest access restriction: Same access as members (most inclusive)" ;;
  "10dae51f-b6af-4016-8d66-8c2a99b929b3")
    echo "Guest access restriction: Limited access to properties and memberships" ;;
  "2af84b1e-32c8-42b7-82bc-daa82404023b")
    echo "Guest access restriction: Restricted to own directory objects (most restrictive)" ;;
  *)
    echo "Guest access restriction: Unknown - $GUEST_ROLE" ;;
esac

echo ""
echo "--- Administration Center ---"
RESTRICT=$(echo $SETTINGS | jq -r '
  .value[]
  | select(.displayName == "Authorization Policy")
  | .values[]
  | select(.name == "RestrictNonAdminUsers")
  | .value')

if [ -z "$RESTRICT" ]; then
  RESTRICT="false (default - not restricted)"
fi
echo "Restrict access to Entra admin center    : $RESTRICT"

echo ""
