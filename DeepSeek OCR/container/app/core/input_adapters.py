"""
Input Adapters for DeepSeek OCR

This module provides functions to handle various input formats:
- HTTP/HTTPS URLs
- S3 URIs (s3://bucket/key)
- Base64 encoded data
- Raw bytes

All adapters convert inputs to temporary file paths for processing.
"""

import os
import tempfile
import logging
from typing import Union

import requests
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException

log = logging.getLogger("deepseek-ocr-transformers")


def download_http(url: str) -> str:
    """
    Download file from HTTP/HTTPS URL.

    Args:
        url: HTTP or HTTPS URL to download

    Returns:
        Path to temporary file containing downloaded content

    Raises:
        HTTPException: If download fails
    """
    log.info(f"Downloading from URL: {url[:100]}...")
    try:
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        suffix = os.path.splitext(url.split("?")[0])[-1] or ".bin"
        fd, tmp = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "wb") as f:
            f.write(r.content)
        log.info(f"✓ Downloaded {len(r.content)} bytes")
        return tmp
    except requests.RequestException as e:
        log.error(f"✗ HTTP download failed: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to download from URL: {str(e)}")


def download_s3(uri: str) -> str:
    """
    Download file from S3.

    Args:
        uri: S3 URI in format s3://bucket/key

    Returns:
        Path to temporary file containing downloaded content

    Raises:
        HTTPException: If download fails
        ValueError: If URI is not a valid s3:// URI
    """
    if not uri.startswith("s3://"):
        raise ValueError("Not an s3:// URI")
    _, _, rest = uri.partition("s3://")
    bucket, _, key = rest.partition("/")

    log.info(f"Downloading from S3: s3://{bucket}/{key}")

    try:
        s3 = boto3.client("s3")
        fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(key)[-1] or ".bin")
        with os.fdopen(fd, "wb") as f:
            s3.download_fileobj(bucket, key, f)
        log.info(f"✓ S3 download complete")
        return tmp
    except (BotoCoreError, ClientError) as e:
        log.error(f"✗ S3 download failed: {e}")
        raise HTTPException(status_code=400, detail=f"S3 download failed: {str(e)}")


def bytes_to_tempfile(data: bytes, suffix: str = ".bin") -> str:
    """
    Write bytes to temporary file.

    Args:
        data: Binary data to write
        suffix: File extension for temporary file

    Returns:
        Path to temporary file
    """
    fd, tmp = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return tmp


def image_to_path(source: Union[str, bytes]) -> str:
    """
    Convert image source to file path.

    Handles multiple input formats:
    - bytes/bytearray: Write to temp file
    - HTTP/HTTPS URL: Download to temp file
    - S3 URI: Download to temp file
    - Local path: Return as-is

    Args:
        source: Image source (bytes, URL, or path)

    Returns:
        Path to image file

    Raises:
        HTTPException: If download fails
    """
    if isinstance(source, (bytes, bytearray)):
        return bytes_to_tempfile(source, suffix=".jpg")

    # String path or URL
    s = str(source)
    if s.startswith(("http://", "https://")):
        return download_http(s)
    elif s.startswith("s3://"):
        return download_s3(s)
    else:
        return s
