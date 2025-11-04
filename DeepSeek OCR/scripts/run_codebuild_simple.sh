#!/bin/bash

# Simple CodeBuild Runner - Uses existing IAM role
# ================================================

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Navigate to repo root (2 levels up from scripts/)
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Change to repo root for all operations
cd "${REPO_ROOT}"

AWS_REGION=${AWS_DEFAULT_REGION:-us-west-2}
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
PROJECT_NAME="deepseek-ocr-byoc-build"
S3_BUCKET="sagemaker-${AWS_REGION}-${AWS_ACCOUNT_ID}"
SOURCE_ZIP="deepseek-ocr-source.zip"

# Use existing SageMaker CodeBuild role
ROLE_NAME="AmazonSageMakerServiceCatalogProductsCodeBuildRole"
ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/service-role/${ROLE_NAME}"

echo "🏗️  Running AWS CodeBuild for DeepSeek OCR"
echo "Region: ${AWS_REGION}"
echo "Project: ${PROJECT_NAME}"
echo "Working from: ${REPO_ROOT}"

# Step 1: Create/verify S3 bucket
echo "📦 Checking S3 bucket..."
aws s3 ls s3://${S3_BUCKET} >/dev/null 2>&1 || aws s3 mb s3://${S3_BUCKET} --region ${AWS_REGION}

# Step 2: Zip source code
echo "📁 Creating source archive..."
python3 "${REPO_ROOT}/DeepSeek OCR/scripts/create_source_zip.py"

# Step 3: Upload to S3
echo "⬆️  Uploading to S3..."
aws s3 cp ${SOURCE_ZIP} s3://${S3_BUCKET}/codebuild/${SOURCE_ZIP}

# Step 4: Create or update CodeBuild project
echo "🏗️  Setting up CodeBuild project..."

if aws codebuild batch-get-projects --names ${PROJECT_NAME} --query 'projects[0].name' --output text 2>/dev/null | grep -q ${PROJECT_NAME}; then
    echo "Updating existing project..."
    aws codebuild update-project \
        --name ${PROJECT_NAME} \
        --source type=S3,location=${S3_BUCKET}/codebuild/${SOURCE_ZIP},buildspec="buildspec.yml" \
        --artifacts type=NO_ARTIFACTS \
        --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:7.0,computeType=BUILD_GENERAL1_LARGE,privilegedMode=true \
        --service-role ${ROLE_ARN} >/dev/null
else
    echo "Creating new project..."
    aws codebuild create-project \
        --name ${PROJECT_NAME} \
        --source type=S3,location=${S3_BUCKET}/codebuild/${SOURCE_ZIP},buildspec="buildspec.yml" \
        --artifacts type=NO_ARTIFACTS \
        --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:7.0,computeType=BUILD_GENERAL1_LARGE,privilegedMode=true \
        --service-role ${ROLE_ARN} >/dev/null
fi

# Step 5: Start build
echo "🚀 Starting build..."
BUILD_ID=$(aws codebuild start-build --project-name ${PROJECT_NAME} --query 'build.id' --output text)

echo ""
echo "✅ Build started!"
echo "Build ID: ${BUILD_ID}"
echo ""
echo "📊 View in console:"
echo "   https://${AWS_REGION}.console.aws.amazon.com/codesuite/codebuild/${AWS_ACCOUNT_ID}/projects/${PROJECT_NAME}/build/${BUILD_ID}"
echo ""

# Monitor build status
echo "⏳ Monitoring build (this takes ~5-10 minutes for Docker build)..."
echo ""

while true; do
    BUILD_STATUS=$(aws codebuild batch-get-builds --ids ${BUILD_ID} --query 'builds[0].buildStatus' --output text)
    BUILD_PHASE=$(aws codebuild batch-get-builds --ids ${BUILD_ID} --query 'builds[0].currentPhase' --output text)

    if [ "$BUILD_STATUS" == "IN_PROGRESS" ]; then
        echo "   Status: ${BUILD_STATUS} | Phase: ${BUILD_PHASE}"
        sleep 15
    else
        break
    fi
done

echo ""
if [ "$BUILD_STATUS" == "SUCCEEDED" ]; then
    echo "✅ Build completed successfully!"
    echo ""
    echo "🎉 Your Docker image is ready:"
    echo "   ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/deepseek-ocr-sagemaker-byoc:latest"
    echo ""
    echo "Next step: Deploy to SageMaker using notebooks/deepseek_ocr_demo.ipynb"
else
    echo "❌ Build failed with status: ${BUILD_STATUS}"
    echo ""
    echo "View logs:"
    LOG_URL=$(aws codebuild batch-get-builds --ids ${BUILD_ID} --query 'builds[0].logs.deepLink' --output text)
    echo "   ${LOG_URL}"
fi

# Cleanup
rm -f ${SOURCE_ZIP}
