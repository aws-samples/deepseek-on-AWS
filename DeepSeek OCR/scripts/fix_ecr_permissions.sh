#!/bin/bash

# ECR Permissions Fix Script for DeepSeek OCR CodeBuild
# ======================================================
# This script diagnoses and fixes ECR permission issues for the CodeBuild role

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ROLE_NAME="AmazonSageMakerServiceCatalogProductsCodeBuildRole"
POLICY_NAME="DeepSeekOCR-ECR-Access"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_FILE="${SCRIPT_DIR}/ecr-codebuild-policy.json"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DeepSeek OCR - ECR Permissions Fix${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Check if AWS CLI is configured
echo -e "${BLUE}[1/5]${NC} Checking AWS CLI configuration..."
if ! aws sts get-caller-identity &>/dev/null; then
    echo -e "${RED}ERROR: AWS CLI is not configured or credentials are invalid${NC}"
    echo "Please run: aws configure"
    exit 1
fi

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=$(aws configure get region || echo "us-east-1")
echo -e "${GREEN}✓${NC} AWS Account: ${AWS_ACCOUNT_ID}"
echo -e "${GREEN}✓${NC} AWS Region: ${AWS_REGION}"
echo ""

# Step 2: Check if role exists
echo -e "${BLUE}[2/5]${NC} Checking if CodeBuild role exists..."
if aws iam get-role --role-name "${ROLE_NAME}" &>/dev/null; then
    echo -e "${GREEN}✓${NC} Role exists: ${ROLE_NAME}"
    ROLE_EXISTS=true
else
    echo -e "${YELLOW}⚠${NC}  Role does not exist: ${ROLE_NAME}"
    ROLE_EXISTS=false
fi
echo ""

# Step 3: Check current permissions if role exists
if [ "$ROLE_EXISTS" = true ]; then
    echo -e "${BLUE}[3/5]${NC} Checking current ECR permissions..."

    # Get all attached and inline policies
    ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name "${ROLE_NAME}" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || echo "")
    INLINE_POLICIES=$(aws iam list-role-policies --role-name "${ROLE_NAME}" --query 'PolicyNames' --output text 2>/dev/null || echo "")

    # Check for ECR permissions in attached AWS managed policies
    HAS_ECR_FULL=false
    HAS_ECR_POWER=false

    if echo "$ATTACHED_POLICIES" | grep -q "AmazonEC2ContainerRegistryFullAccess"; then
        HAS_ECR_FULL=true
    fi
    if echo "$ATTACHED_POLICIES" | grep -q "AmazonEC2ContainerRegistryPowerUser"; then
        HAS_ECR_POWER=true
    fi

    # Check if our custom policy is already attached
    HAS_CUSTOM_POLICY=false
    if echo "$INLINE_POLICIES" | grep -q "${POLICY_NAME}"; then
        HAS_CUSTOM_POLICY=true
    fi

    if [ "$HAS_ECR_FULL" = true ] || [ "$HAS_ECR_POWER" = true ] || [ "$HAS_CUSTOM_POLICY" = true ]; then
        echo -e "${GREEN}✓${NC} Role has ECR permissions"
        if [ "$HAS_ECR_FULL" = true ]; then
            echo "  - Has AmazonEC2ContainerRegistryFullAccess"
        fi
        if [ "$HAS_ECR_POWER" = true ]; then
            echo "  - Has AmazonEC2ContainerRegistryPowerUser"
        fi
        if [ "$HAS_CUSTOM_POLICY" = true ]; then
            echo "  - Has custom policy: ${POLICY_NAME}"
        fi
        echo ""
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}No action needed! Permissions are OK.${NC}"
        echo -e "${GREEN}========================================${NC}"
        exit 0
    else
        echo -e "${YELLOW}⚠${NC}  Role exists but missing ECR permissions"
        NEEDS_PERMISSIONS=true
    fi
else
    echo -e "${BLUE}[3/5]${NC} Skipping permission check (role doesn't exist)..."
    NEEDS_PERMISSIONS=true
fi
echo ""

# Step 4: Offer to fix
echo -e "${BLUE}[4/5]${NC} Determining fix strategy..."
echo ""

if [ "$ROLE_EXISTS" = false ]; then
    echo -e "${YELLOW}Issue found:${NC}"
    echo "  The CodeBuild role '${ROLE_NAME}' does not exist."
    echo ""
    echo -e "${BLUE}This role is normally created automatically by SageMaker Service Catalog.${NC}"
    echo ""
    echo "Recommended fixes:"
    echo "  1. ${GREEN}Use SageMaker Service Catalog${NC} (creates role automatically)"
    echo "     - Go to SageMaker console > Projects > Create Project"
    echo "     - This will create the required role"
    echo ""
    echo "  2. ${GREEN}Create role manually${NC}"
    echo "     - You'll need additional permissions to create IAM roles"
    echo ""

    read -p "Do you want to attempt to create the role now? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting. Please create the role manually or use SageMaker Service Catalog."
        exit 0
    fi

    echo ""
    echo "Creating role ${ROLE_NAME}..."

    # Create trust policy for CodeBuild
    TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
)

    if aws iam create-role \
        --role-name "${ROLE_NAME}" \
        --assume-role-policy-document "$TRUST_POLICY" \
        --description "CodeBuild role for DeepSeek OCR with ECR permissions" \
        &>/dev/null; then
        echo -e "${GREEN}✓${NC} Role created successfully"
    else
        echo -e "${RED}✗${NC} Failed to create role"
        echo "You may not have iam:CreateRole permission."
        echo "Please ask your AWS administrator to create this role or grant you permissions."
        exit 1
    fi
elif [ "$NEEDS_PERMISSIONS" = true ]; then
    echo -e "${YELLOW}Issue found:${NC}"
    echo "  The role exists but is missing required ECR permissions."
    echo ""
    echo -e "${BLUE}Required permissions:${NC}"
    echo "  - ecr:GetAuthorizationToken"
    echo "  - ecr:CreateRepository"
    echo "  - ecr:DescribeRepositories"
    echo "  - ecr:BatchCheckLayerAvailability"
    echo "  - ecr:PutImage"
    echo "  - ecr:InitiateLayerUpload"
    echo "  - ecr:UploadLayerPart"
    echo "  - ecr:CompleteLayerUpload"
    echo ""

    read -p "Do you want to add these permissions now? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting. Please add permissions manually."
        exit 0
    fi
fi
echo ""

# Step 5: Apply fix
echo -e "${BLUE}[5/5]${NC} Applying fix..."

# Check if policy file exists
if [ ! -f "${POLICY_FILE}" ]; then
    echo -e "${RED}✗${NC} Policy file not found: ${POLICY_FILE}"
    exit 1
fi

# Attach inline policy
echo "Attaching ECR permissions policy..."
if aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "${POLICY_NAME}" \
    --policy-document "file://${POLICY_FILE}" \
    &>/dev/null; then
    echo -e "${GREEN}✓${NC} ECR permissions added successfully"
else
    echo -e "${RED}✗${NC} Failed to attach policy"
    echo "You may not have iam:PutRolePolicy permission."
    echo "Please ask your AWS administrator to add these permissions."
    exit 1
fi
echo ""

# Step 6: Verify
echo -e "${BLUE}Verifying fix...${NC}"
sleep 2
if aws iam get-role-policy --role-name "${ROLE_NAME}" --policy-name "${POLICY_NAME}" &>/dev/null; then
    echo -e "${GREEN}✓${NC} Policy successfully attached to role"
else
    echo -e "${RED}✗${NC} Verification failed"
    exit 1
fi
echo ""

# Success summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ ECR Permissions Fixed Successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Summary:"
echo "  - Role: ${ROLE_NAME}"
echo "  - Policy: ${POLICY_NAME}"
echo "  - Permissions: ECR Full Access (Create, Push, Describe)"
echo ""
echo "You can now run the CodeBuild script:"
echo -e "  ${BLUE}cd 'DeepSeek OCR/scripts' && ./run_codebuild_simple.sh${NC}"
echo ""
