# DeepSeek OCR SageMaker BYOC with Transformers
# Using NVIDIA NGC registry (no rate limits like Docker Hub)
# CUDA 12.4 required for PyTorch 2.6.0 (fixes CRITICAL RCE CVE)
FROM nvcr.io/nvidia/cuda:12.4.1-devel-ubuntu22.04

# System packages
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3.10 \
        python3-pip \
        python3.10-dev \
        build-essential \
        git \
        curl \
        libgl1 \
        libglib2.0-0 && \
    rm -rf /var/lib/apt/lists/*

# Set Python 3.10 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1 && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3.10 1

# Upgrade pip
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel

# Install PyTorch with CUDA 12.4 (2.6.0 fixes CRITICAL RCE CVE in torch.load)
RUN pip install --no-cache-dir \
    torch==2.6.0 \
    torchvision==0.21.0 \
    --index-url https://download.pytorch.org/whl/cu124

# Install ninja and psutil (required for flash-attn compilation)
RUN pip install --no-cache-dir ninja psutil packaging

# Install flash-attn (required for DeepSeek-OCR)
RUN pip install --no-cache-dir flash-attn==2.7.3 --no-build-isolation

# Install Transformers and core deps
RUN pip install --no-cache-dir \
    transformers==4.46.3 \
    tokenizers==0.20.3 \
    accelerate \
    einops \
    addict \
    easydict

# Install web framework
RUN pip install --no-cache-dir \
    fastapi==0.115.5 \
    uvicorn[standard]==0.32.1 \
    pydantic==2.10.3

# Install image/PDF processing
RUN pip install --no-cache-dir \
    Pillow==11.0.0 \
    pypdfium2==4.30.0

# Install AWS SDK and HuggingFace transfer
RUN pip install --no-cache-dir \
    boto3==1.35.91 \
    requests==2.32.3 \
    hf-transfer

# Copy application code
WORKDIR /opt/program
COPY container/app /opt/program/app

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    MODEL_ID=deepseek-ai/DeepSeek-OCR \
    HF_HOME=/opt/hf \
    HF_HUB_ENABLE_HF_TRANSFER=1 \
    TRANSFORMERS_CACHE=/opt/hf

# Create simple serve script
RUN echo '#!/bin/bash\nexec python3 -m uvicorn app.server:app --host 0.0.0.0 --port 8080 --log-level info' > /opt/program/serve && \
    chmod +x /opt/program/serve

# SageMaker compatible entrypoint
ENTRYPOINT ["/opt/program/serve"]
CMD []

EXPOSE 8080
