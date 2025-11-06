# DeepSeek-OCR on Amazon SageMaker

Deploy the **DeepSeek-OCR** vision-language model on Amazon SageMaker with synchronous and asynchronous inference using a Bring-Your-Own-Container (BYOC) approach with PyTorch and Transformers.

## Features

- **Sync + Async Inference**: Real-time endpoint + SageMaker AsyncInferenceConfig for long-running tasks
- **PyTorch/Transformers backend**: Official DeepSeek-OCR implementation with thread-safe model management
- **Multi-format support**: Single images, multi-page PDFs (100+ pages), URLs, base64, S3 URIs
- **Production-ready**: SageMaker hosting contract (`/ping`, `/invocations`)
- **Flexible prompts**: Free OCR or markdown conversion with bounding boxes
- **Type-safe configuration**: Environment-based configuration with validation
- **Comprehensive tests**: 100+ unit tests with 100% backward compatibility
- **Easy deployment**: CodeBuild automation or local Docker build

## What is DeepSeek-OCR?

DeepSeek-OCR is a state-of-the-art vision-language model for optical character recognition tasks. It excels at:
- Extracting text from documents, invoices, receipts, and forms
- Processing handwritten content from whiteboards and notes
- Converting documents to structured Markdown format
- Providing bounding box coordinates for detected text (grounding mode)
- Handling large, complex documents with 100+ pages

**Model Card**: [deepseek-ai/DeepSeek-OCR on HuggingFace](https://huggingface.co/deepseek-ai/DeepSeek-OCR)

## Architecture

### Synchronous Inference (Real-Time)

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTP POST /invocations
       ▼
┌────────────────────────────────────────┐
│       SageMaker Endpoint               │
│       (ml.g5.2xlarge)                  │
│  ┌──────────────────────────────────┐  │
│  │  FastAPI (port 8080)             │  │
│  │  ┌────────────────────────────┐  │  │
│  │  │ /invocations (Sync)        │  │  │
│  │  │ └─60s timeout              │  │  │
│  │  └─────────┬──────────────────┘  │  │
│  │            │                      │  │
│  │  ┌─────────▼─────────────────┐   │  │
│  │  │ Thread-Safe ModelService  │   │  │
│  │  │ (Singleton Pattern)       │   │  │
│  │  └─────────┬─────────────────┘   │  │
│  │            │                      │  │
│  │  ┌─────────▼─────────────────┐   │  │
│  │  │ Transformers              │   │  │
│  │  │ DeepSeek-OCR Model        │   │  │
│  │  │ (8GB, bfloat16)           │   │  │
│  │  └───────────────────────────┘   │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
          │
          │ JSON Response
          ▼
    ┌─────────────┐
    │   Client    │
    └─────────────┘
```

### Asynchronous Inference (Long-Running via SageMaker)

```
┌─────────────┐                    ┌──────────────────┐
│   Client    │──1. Upload────────▶│   S3 Bucket      │
└──────┬──────┘    input.json      │   (Input)        │
       │                            └──────────────────┘
       │ 2. invoke_endpoint_async()
       ▼
┌─────────────────────────────────────────────────────┐
│       SageMaker AsyncInferenceConfig                │
│  ┌───────────────────────────────────────────────┐  │
│  │  3. Downloads input from S3                   │  │
│  │  4. Calls container /invocations (sync HTTP)  │  │
│  │  5. Uploads result to S3                      │  │
│  │  6. Publishes SNS notification (optional)     │  │
│  └───────────────────────────────────────────────┘  │
└──────────────────┬──────────────────────────────────┘
                   │ 4. HTTP POST /invocations
                   ▼
┌────────────────────────────────────────┐
│       SageMaker Endpoint               │
│       (ml.g5.2xlarge)                  │
│  ┌──────────────────────────────────┐  │
│  │  FastAPI (port 8080)             │  │
│  │  ┌────────────────────────────┐  │  │
│  │  │ /invocations (Sync)        │  │  │
│  │  │ └─Processes as normal      │  │  │
│  │  └─────────┬──────────────────┘  │  │
│  │            │                      │  │
│  │  ┌─────────▼─────────────────┐   │  │
│  │  │ DeepSeek-OCR Model        │   │  │
│  │  └───────────────────────────┘   │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
          │
          │ 5. Result
          ▼
    ┌──────────────────┐         ┌──────────┐
    │   S3 Bucket      │         │ Amazon   │
    │   (Output)       │◀────────│   SNS    │
    └────────┬─────────┘         └──────────┘
             │ 7. Download                ▲
             ▼                            │ 6. Notification
       ┌─────────────┐                    │
       │   Client    │────────────────────┘
       └─────────────┘

**Note**: Container only needs `/invocations` endpoint. SageMaker handles all async orchestration (S3 I/O, queuing, timeouts, SNS notifications).
```

## Quick Start

### Prerequisites

- AWS Account with SageMaker permissions
- AWS CLI configured
- Docker (for local builds) or CodeBuild (for AWS builds)

### Option A: CodeBuild (Recommended)

Build and push the container image using AWS CodeBuild:

```bash
cd "DeepSeek OCR/scripts"
./run_codebuild_simple.sh
```

This will:
1. Upload source code to S3
2. Trigger CodeBuild project
3. Build Docker image (~15-20 minutes)
4. Push to Amazon ECR

### Option B: Local Docker Build

Build and push the container locally:

```bash
# Set variables
export AWS_REGION=us-west-2
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export REPO=deepseek-ocr-sagemaker-byoc

# Login to ECR
aws ecr get-login-password --region $AWS_REGION | \
    docker login --username AWS --password-stdin \
    $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Create repository if needed
aws ecr create-repository --repository-name $REPO --region $AWS_REGION 2>/dev/null || true

# Build and push
cd "DeepSeek OCR"
docker build -t $REPO:latest -f container/Dockerfile .
docker tag $REPO:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:latest
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:latest
```

### Deploy to SageMaker

Open and run the demo notebook:

```
notebooks/deepseek_ocr_demo.ipynb
```

The notebook walks through:
1. Creating a SageMaker model
2. Configuring the endpoint
3. Deploying the endpoint (~5-10 minutes)
4. Testing with images and PDFs (sync and async)
5. Setting up SNS topics for async notifications
6. Cleaning up resources

## Usage Examples

### Synchronous Endpoint (Real-Time)

#### Single Image OCR

```python
import boto3
import json
import base64

runtime = boto3.client('sagemaker-runtime')

# Read image
with open("invoice.jpg", "rb") as f:
    img_base64 = base64.b64encode(f.read()).decode("utf-8")

# Invoke endpoint
payload = {
    "prompt": "<image>\\nFree OCR.",
    "image_base64": img_base64
}

response = runtime.invoke_endpoint(
    EndpointName='your-endpoint-name',
    ContentType='application/json',
    Body=json.dumps(payload)
)

result = json.loads(response['Body'].read())
print(result['text'])
```

#### Image from URL or S3

```python
# From HTTP URL
payload = {
    "prompt": "<image>\\nFree OCR.",
    "image_url": "https://example.com/document.jpg"
}

# From S3 URI
payload = {
    "prompt": "<image>\\nFree OCR.",
    "image_url": "s3://my-bucket/documents/invoice.jpg"
}
```

#### Small PDF Processing

```python
# Process a 1-2 page PDF
payload = {
    "prompt": "<image>\\nFree OCR.",
    "pdf_url": "https://example.com/document.pdf"
}

response = runtime.invoke_endpoint(
    EndpointName='your-endpoint-name',
    ContentType='application/json',
    Body=json.dumps(payload)
)

result = json.loads(response['Body'].read())
print(f"Processed {result['pages']} pages")
print(result['text'])
```

**Note**: Sync endpoint has 60-second timeout. For large PDFs (3+ pages), use SageMaker AsyncInferenceConfig.

### Asynchronous Inference (Long-Running Tasks via SageMaker)

For long-running tasks (large PDFs), use SageMaker's AsyncInferenceConfig. The container processes requests normally via `/invocations`, while SageMaker handles async orchestration.

#### Setup Async Endpoint

```python
import boto3
import sagemaker

sagemaker_client = boto3.client('sagemaker')

# Create endpoint config with AsyncInferenceConfig
async_config = {
    'OutputConfig': {
        'S3OutputPath': 's3://your-bucket/async-results/',
        # Optional SNS notification
        'NotificationConfig': {
            'SuccessTopic': 'arn:aws:sns:region:account:topic-name',
            'ErrorTopic': 'arn:aws:sns:region:account:topic-name'
        }
    }
}

response = sagemaker_client.create_endpoint_config(
    EndpointConfigName='deepseek-ocr-async-config',
    ProductionVariants=[{
        'VariantName': 'AllTraffic',
        'ModelName': 'deepseek-ocr-model',
        'InstanceType': 'ml.g5.2xlarge',
        'InitialInstanceCount': 1
    }],
    AsyncInferenceConfig=async_config
)
```

#### Large PDF Processing with Async

```python
import boto3
import json
import time

s3 = boto3.client('s3')
runtime = boto3.client('sagemaker-runtime')

bucket = 'your-bucket'
input_key = 'async-inputs/request.json'
output_prefix = 'async-results/'

# 1. Upload input to S3
payload = {
    "pdf_url": "s3://my-bucket/large-document.pdf",
    "prompt": "<image>\\n<|grounding|>Convert to markdown."
}
s3.put_object(
    Bucket=bucket,
    Key=input_key,
    Body=json.dumps(payload),
    ContentType='application/json'
)

# 2. Invoke async endpoint
response = runtime.invoke_endpoint_async(
    EndpointName='your-async-endpoint-name',
    InputLocation=f's3://{bucket}/{input_key}'
)

output_location = response['OutputLocation']
print(f"Request submitted. Output will be at: {output_location}")

# 3. Poll for results (or use SNS notification)
while True:
    try:
        result = s3.get_object(
            Bucket=bucket,
            Key=output_location.split(bucket + '/')[1]
        )
        ocr_result = json.loads(result['Body'].read())
        print(f"Processed {ocr_result['pages']} pages")
        print(ocr_result['text'])
        break
    except s3.exceptions.NoSuchKey:
        print("Waiting for processing...")
        time.sleep(10)
```

#### Receiving Results via SNS Notification

When you configure SNS topics in AsyncInferenceConfig, SageMaker publishes notifications:

```json
{
  "invocationStatus": "Completed",
  "requestParameters": {
    "inputLocation": "s3://bucket/async-inputs/request.json"
  },
  "responseParameters": {
    "outputLocation": "s3://bucket/async-results/output.json"
  },
  "inferenceId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

Download the result from `outputLocation`:
```json
{
  "text": "# Document Title\n\n## Page 1\n\nExtracted text...",
  "pages": 15
}
```

### Markdown with Bounding Boxes (Grounding Mode)

```python
payload = {
    "prompt": "<image>\\n<|grounding|>Convert the document to markdown.",
    "image_base64": img_base64
}
```

This returns structured markdown with bounding box coordinates in format:
```
<|ref|>text<|/ref|><|det|>[[x1, y1, x2, y2]]<|/det|>
Header Text
```

## API Reference

### Endpoint: `/ping`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "model": "deepseek-ai/DeepSeek-OCR",
  "backend": "transformers"
}
```

### Endpoint: `/health`
Detailed health check with model status.

**Response:**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "model_id": "deepseek-ai/DeepSeek-OCR",
  "backend": "transformers",
  "uptime_seconds": 3600.5,
  "error": null
}
```

### Endpoint: `/invocations` (Synchronous)

**Timeout:** 60 seconds

**Request Format:**
```json
{
  "prompt": "<image>\\nFree OCR.",
  "image_url": "https://example.com/image.jpg",    // OR
  "image_base64": "base64-encoded-image-data",     // OR
  "pdf_url": "https://example.com/doc.pdf",        // OR
  "pdf_base64": "base64-encoded-pdf-data"
}
```

**Response Format:**
```json
{
  "text": "Extracted text content...",
  "pages": 3  // Only present for PDF inputs
}
```

**Note**: For async inference with long-running tasks, use SageMaker AsyncInferenceConfig (documented above). The container only needs the `/invocations` endpoint.

## Environment Variables

Configure the container at deployment time:

### Model Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_ID` | `deepseek-ai/DeepSeek-OCR` | HuggingFace model ID |
| `DEVICE` | `cuda` | Compute device (cuda, cpu, auto) |
| `DTYPE` | `bfloat16` | Model precision (bfloat16, float16, float32) |
| `BASE_SIZE` | `1024` | Base image size for processing |
| `IMAGE_SIZE` | `640` | Target image size |
| `CROP_MODE` | `true` | Enable image cropping |

### Server Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_PROMPT` | `<image>\\n<|grounding|>Convert to markdown.` | Default OCR prompt |
| `MAX_TIMEOUT` | `60` | Endpoint timeout (seconds) |
| `PORT` | `8080` | Server port |
| `WORKERS` | `1` | Number of workers (keep at 1 for model singleton) |

### AWS Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | `us-east-1` | AWS region for S3 downloads |
| `S3_DOWNLOAD_TIMEOUT` | `300` | S3 download timeout (seconds) |

### Other Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `prod` | Environment (dev, staging, prod) |
| `DEBUG` | `false` | Enable debug logging |
| `HF_HUB_ENABLE_HF_TRANSFER` | `1` | Enable fast model downloads |
| `TRANSFORMERS_CACHE` | `/opt/hf` | Model cache directory |

## Instance Recommendations

| Use Case | Instance Type | GPU | vCPU | Memory | Cost/Hour* |
|----------|---------------|-----|------|--------|------------|
| Development/Testing | `ml.g5.xlarge` | 1x A10G (24GB) | 4 | 16GB | ~$1.41 |
| **Production (Recommended)** | `ml.g5.2xlarge` | 1x A10G (24GB) | 8 | 32GB | ~$1.52 |
| High Traffic | `ml.g5.4xlarge` | 1x A10G (24GB) | 16 | 64GB | ~$2.03 |

*Prices vary by region. Check [SageMaker Pricing](https://aws.amazon.com/sagemaker/pricing/) for current rates.

**Recommendation**: Start with `ml.g5.2xlarge` for good balance of performance and cost.

## Performance Characteristics

### Synchronous Endpoint
| Document Type | Processing Time | Notes |
|---------------|----------------|-------|
| Single image | 2-5 seconds | Depends on resolution and complexity |
| Small PDF (1-2 pages) | 5-10 seconds | Sequential page processing |
| Handwritten text | 3-6 seconds | Accuracy depends on handwriting clarity |

**Timeout**: 60 seconds

### SageMaker Async Inference
For long-running tasks, SageMaker AsyncInferenceConfig provides:
- Up to 1 hour processing time
- S3-based input/output
- Optional SNS notifications
- Automatic queuing and retry

**See SageMaker Async section above for configuration details**

### First Request
- Model loading (first request only): 3-5 minutes
- Includes 8GB model download + GPU loading
- Subsequent requests are fast (model cached)

## Project Structure

```
DeepSeek OCR/
├── container/
│   ├── Dockerfile                    # Container definition
│   ├── app/
│   │   ├── server.py                 # FastAPI server with sync endpoint
│   │   └── core/                     # Shared components
│   │       ├── __init__.py
│   │       ├── config.py             # Configuration management
│   │       ├── model_service.py      # Thread-safe model singleton
│   │       ├── input_adapters.py     # HTTP/S3/base64 input handling
│   │       ├── pdf_processor.py      # PDF to image conversion
│   │       └── inference_engine.py   # Core OCR inference logic
│   └── requirements.txt              # Dependency documentation
├── tests/
│   ├── conftest.py                   # Shared test fixtures
│   ├── pytest.ini                    # Test configuration
│   ├── requirements-test.txt         # Test dependencies
│   ├── unit/                         # Unit tests
│   │   ├── test_config.py            # Configuration tests
│   │   ├── test_model_service.py     # Thread safety tests
│   │   ├── test_inference_engine.py  # Inference logic tests
│   │   ├── test_input_adapters.py    # Input handling tests
│   │   ├── test_pdf_processor.py     # PDF processing tests
│   │   └── test_sync_endpoint_baseline.py  # Sync endpoint tests
│   └── README.md                     # Test documentation
├── notebooks/
│   └── deepseek_ocr_demo.ipynb       # Deployment and usage demo
├── scripts/
│   ├── run_codebuild_simple.sh       # Build with CodeBuild
│   └── create_source_zip.py          # Package for CodeBuild
├── buildspec.yml                     # CodeBuild configuration
└── README.md                         # This file
```

## Architecture Highlights

### Thread-Safe Model Service
- **Singleton pattern** ensures model loaded once (8GB saved)
- **Double-checked locking** for concurrent access
- **Lazy loading** on first request
- **Error tracking** with detailed diagnostics
- Supports async/await with FastAPI background tasks

### Type-Safe Configuration
- **Environment-based** configuration with validation
- **Dataclass models** for type safety
- **Multiple environments** (dev, staging, prod)
- **30+ configurable settings** for fine-tuning

### Shared Components
- **Modular architecture** with reusable components
- **Input adapters** for HTTP/S3/base64
- **PDF processor** with pypdfium2
- **Inference engine** with configurable parameters

### Comprehensive Testing
- **125 unit tests** with 100% backward compatibility
- **10-second test runtime** for rapid iteration
- **Mock-based testing** (no GPU required)
- **Thread safety verification** with stress tests

## Docker Image Details

### Base Image
```dockerfile
FROM nvcr.io/nvidia/cuda:12.1.0-devel-ubuntu22.04
```

Uses NVIDIA NGC registry (no Docker Hub rate limits) with CUDA 12.1 development tools for compiling flash-attention.

### Key Dependencies
- **PyTorch** 2.5.1 with CUDA 12.1
- **Transformers** 4.46.3 (official DeepSeek-OCR backend)
- **flash-attn** 2.7.3 (required for model performance)
- **FastAPI** + **uvicorn** (web server with async support)
- **pypdfium2** (PDF processing)
- **boto3** (S3 and SNS access)
- **hf-transfer** (fast model downloads)

### Build Time
- **Total**: 15-20 minutes
- Most time spent compiling flash-attention (~8-10 minutes)

## Testing

### Running Tests

```bash
# Install test dependencies
pip install -r tests/requirements-test.txt

# Run all tests
pytest tests/unit/ -v

# Run specific test file
pytest tests/unit/test_config.py -v

# Run with coverage
pytest tests/unit/ --cov=container/app --cov-report=html

# Run only fast tests (skip slow tests)
pytest tests/unit/ -m "not slow"
```

### Test Coverage
- **100+ unit tests** with fast execution
- **Unit tests**: Sync endpoint, configuration, model service, inference engine
- **Integration tests**: HTTP/S3 downloads, PDF processing
- **Thread safety**: Concurrent access tests with 100 threads
- **100% backward compatibility**: All baseline tests maintained

## Troubleshooting

### Endpoint Creation Fails

**Check CloudWatch Logs:**
```bash
# Find log group
aws logs describe-log-groups --log-group-name-prefix "/aws/sagemaker/Endpoints"

# View recent logs
aws logs tail /aws/sagemaker/Endpoints/your-endpoint-name --follow
```

**Common Issues:**
- Model download timeout: Ensure `HF_HUB_ENABLE_HF_TRANSFER=1` is set
- OOM errors: Use larger instance (ml.g5.4xlarge)
- Image pull errors: Verify ECR permissions

### /ping Returns 503

**Cause**: Model still loading from HuggingFace (~8GB download + GPU loading)

**Solution**: Wait 3-5 minutes after endpoint shows "InService". Check CloudWatch logs for "✓ MODEL READY!"

### Sync Endpoint Timeout (60s)

**Problem**: Large PDFs timeout after 60 seconds

**Solutions:**
1. **Use async endpoint** (recommended for PDFs with 3+ pages)
2. **Process pages individually** (see notebook example)
3. **Split PDF before processing**

### Async Results Not Appearing in S3

**Problem**: Async inference results not saved to S3

**Check:**
1. AsyncInferenceConfig is properly configured with S3OutputPath
2. SageMaker execution role has S3 write permissions
3. Check SageMaker endpoint logs in CloudWatch
4. Verify async invocation returned OutputLocation in response

### Inference Returns None

**Cause**: Missing `eval_mode=True` parameter in older versions

**Solution**: Ensure you're using the latest image. The parameter is set correctly in the inference engine.

## Development

### Testing Locally

```bash
# Build image
docker build -t deepseek-ocr:test -f container/Dockerfile .

# Run locally
docker run -p 8080:8080 \
    -e MODEL_ID=deepseek-ai/DeepSeek-OCR \
    -e HF_HUB_ENABLE_HF_TRANSFER=1 \
    -e DEBUG=true \
    deepseek-ocr:test

# Test endpoint
curl -X POST http://localhost:8080/invocations \
    -H "Content-Type: application/json" \
    -d '{"prompt":"<image>\\nFree OCR.","image_url":"https://example.com/test.jpg"}'

# Test with PDF
curl -X POST http://localhost:8080/invocations \
    -H "Content-Type: application/json" \
    -d '{"prompt":"<image>\\nFree OCR.","pdf_url":"https://example.com/test.pdf"}'
```

### Modifying the Container

1. Edit `container/app/server.py` to change endpoint logic
2. Edit `container/app/core/` modules for shared logic
3. Edit `container/Dockerfile` to add dependencies
4. Rebuild and push: `./scripts/run_codebuild_simple.sh`
5. Update SageMaker endpoint to use new image

### Adding Custom Features

**Custom Preprocessing:**
Modify `inference_engine.py` to add custom image preprocessing or prompt engineering.

**Custom Result Processing:**
Modify `server.py` to add custom response formatting or metadata enrichment.

**Async Processing Extensions:**
Use SageMaker AsyncInferenceConfig with SNS notifications, custom error handling, or result post-processing via Lambda functions.

## Resources

- **DeepSeek-OCR Model**: [HuggingFace Model Card](https://huggingface.co/deepseek-ai/DeepSeek-OCR)
- **SageMaker BYOC Guide**: [AWS Documentation](https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms.html)
- **SageMaker Endpoints**: [Developer Guide](https://docs.aws.amazon.com/sagemaker/latest/dg/realtime-endpoints.html)
- **SageMaker Async Inference**: [Developer Guide](https://docs.aws.amazon.com/sagemaker/latest/dg/async-inference.html)
- **PyTorch Documentation**: [pytorch.org](https://pytorch.org/docs/)
- **Transformers Library**: [HuggingFace Docs](https://huggingface.co/docs/transformers/)
- **FastAPI Documentation**: [fastapi.tiangolo.com](https://fastapi.tiangolo.com/)

## License

This implementation follows the DeepSeek-OCR model license (MIT). See the [model card](https://huggingface.co/deepseek-ai/DeepSeek-OCR) for details.

## Contributing

Issues and pull requests welcome! This is a sample implementation for AWS blog posts and can be adapted for production use cases.

## Support

For issues specific to:
- **DeepSeek-OCR model**: See the [HuggingFace model repository](https://huggingface.co/deepseek-ai/DeepSeek-OCR/discussions)
- **AWS SageMaker**: Contact AWS Support or see [AWS Forums](https://repost.aws/)
- **This implementation**: Open an issue in this repository

## Changelog

### Version 2.0 (Latest)
- ✅ Added async endpoint for long-running tasks (up to 15 minutes)
- ✅ SNS notifications for async results
- ✅ Thread-safe model service with singleton pattern
- ✅ Type-safe configuration with 30+ environment variables
- ✅ Refactored architecture with shared components
- ✅ Comprehensive test suite (125 tests, 10s runtime)
- ✅ Improved error handling and logging
- ✅ Metadata support for request tracking

### Version 1.0
- Initial release with synchronous endpoint
- Basic PDF support (1-2 pages)
- HTTP/S3/base64 input support
