#!/usr/bin/env bash

# === CONFIG (already filled for your tenant/app) ===
TENANT_ID="8bd45b04-aa1e-4de5-b83c-68ab45726aa5"
SP_OBJECT_ID="20d59267-68cc-49ab-9782-f3643c2d3557"   # Google ADK Portal service principal
USER_ADMIN_TEMPLATE_ID="fe930be7-5e62-47db-91af-98c3a49a38b1"  # User Administrator role template

echo "Using tenant:        $TENANT_ID"
echo "Service principal:   $SP_OBJECT_ID"
echo "User Admin template: $USER_ADMIN_TEMPLATE_ID"
echo

# --- 1. Make sure we're on the right tenant ---
echo "Checking current Azure tenant..."
az account show --query tenantId -o tsv

CURRENT_TENANT=$(az account show --query tenantId -o tsv)
if [ "$CURRENT_TENANT" != "$TENANT_ID" ]; then
  echo "!! WARNING: You are logged into a different tenant ($CURRENT_TENANT)"
  echo "   Please run: az account set --subscription <your-subscription-id> for the correct tenant"
  echo "   and re-run this script."
  exit 1
fi

# --- 2. Find or create the User Administrator directoryRole instance ---
echo
echo "Looking for existing 'User Administrator' directoryRole instance..."

ROLE_ID=$(az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles?\$filter=roleTemplateId eq '$USER_ADMIN_TEMPLATE_ID'" \
  --query "value[0].id" -o tsv 2>/dev/null)

if [ -z "$ROLE_ID" ] || [ "$ROLE_ID" == "None" ]; then
  echo "No active 'User Administrator' directoryRole found. Creating one..."
  ROLE_JSON=$(az rest \
    --method POST \
    --url "https://graph.microsoft.com/v1.0/directoryRoles" \
    --body "{\"roleTemplateId\":\"$USER_ADMIN_TEMPLATE_ID\"}" \
    -o json)

  ROLE_ID=$(echo "$ROLE_JSON" | jq -r '.id')
  echo "Created 'User Administrator' role instance with id: $ROLE_ID"
else
  echo "Found existing 'User Administrator' role instance with id: $ROLE_ID"
fi

# --- 3. Add the service principal as a member of that role ---
echo
echo "Assigning 'User Administrator' role to service principal $SP_OBJECT_ID ..."

ADD_RESULT=$(az rest \
  --method POST \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/$ROLE_ID/members/\$ref" \
  --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/$SP_OBJECT_ID\"}" \
  2>&1)

if echo "$ADD_RESULT" | grep -qi "204"; then
  echo "Assignment request returned 204 No Content (success)."
elif echo "$ADD_RESULT" | grep -qi "added object references"; then
  echo "Service principal successfully added to the 'User Administrator' role."
elif echo "$ADD_RESULT" | grep -qi "One or more added object references already exist"; then
  echo "Service principal already has the 'User Administrator' role."
else
  echo "Raw response from Graph:"
  echo "$ADD_RESULT"
  echo
  echo "If you see an error like 'already exists', it just means the role is already assigned."
fi

echo
echo "Done. Now your 'Google ADK Portal' service principal should have the User Administrator role."
