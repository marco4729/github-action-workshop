#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# =============================
# Variables - Update these!
# =============================
SUBSCRIPTION_ID="7536d87d-5163-4fc3-8154-3d1a335f0baa"
TENANT_ID="c3685dc2-7f3f-4a5c-b20e-f8eca0ae4869"
APP_NAME="github-workload-identity-app"
FEDERATED_CREDENTIALS_NAME="github-actions-federated-credentials"
GITHUB_ORG="marco4729"
GITHUB_REPO="github-action-workshop"
BRANCH="main"  # or specify another branch if needed

# =============================
# Step 1: Create Azure AD Application
# =============================
echo "Creating Azure AD Application..."
APP_ID=$(az ad app create --display-name $APP_NAME --query 'appId' -o tsv)
echo "Created Azure AD Application with App ID: $APP_ID"

# =============================
# Step 2: Create Service Principal
# =============================
echo "Creating Service Principal..."
az ad sp create --id $APP_ID
echo "Service Principal created for App ID: $APP_ID"

# =============================
# Step 3: Assign Contributor Role
# =============================
echo "Assigning Contributor role to Service Principal..."
az role assignment create \
  --assignee $APP_ID \
  --role Contributor \
  --scope /subscriptions/$SUBSCRIPTION_ID
echo "Contributor role assigned to Service Principal"

# =============================
# Step 4: Set Up Federated Credentials
# =============================
echo "Setting up Federated Credentials for GitHub Actions..."
az ad app federated-credential create --id $APP_ID \
  --parameters "{
    \"name\": \"$FEDERATED_CREDENTIALS_NAME\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"repo:$GITHUB_ORG/$GITHUB_REPO:ref:refs/heads/$BRANCH\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }"
echo "Federated credentials created for GitHub repository $GITHUB_ORG/$GITHUB_REPO"

# =============================
# Step 5: Display Output for GitHub Secrets
# =============================
echo "==========================================="
echo "Setup completed successfully!"
echo "Add the following secrets to your GitHub repository:"
echo "==========================================="
echo "AZURE_CLIENT_ID: $APP_ID"
echo "AZURE_TENANT_ID: $TENANT_ID"
echo "AZURE_SUBSCRIPTION_ID: $SUBSCRIPTION_ID"
echo "==========================================="

# Exit script
exit 0
