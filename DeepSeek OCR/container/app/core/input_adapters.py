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
import ipaddress
from typing import Union
from urllib.parse import urlparse
import socket

import requests
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException

log = logging.getLogger("deepseek-ocr-transformers")


def validate_url_ssrf(url: str) -> None:
    """
    Validate URL to prevent SSRF attacks.

    Blocks access to:
    - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Loopback addresses (127.0.0.0/8)
    - Link-local addresses (169.254.0.0/16) - AWS metadata endpoint
    - IPv6 private ranges
    - Other special-use addresses

    Args:
        url: URL to validate

    Raises:
        HTTPException: If URL points to blocked IP range
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            raise HTTPException(
                status_code=400,
                detail="Invalid URL: Missing hostname"
            )

        # Resolve hostname to IP address
        try:
            # Get all IP addresses for hostname
            addr_info = socket.getaddrinfo(hostname, None)
            ip_addresses = [info[4][0] for info in addr_info]
        except socket.gaierror as e:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot resolve hostname: {hostname}"
            )

        # Check each resolved IP address
        for ip_str in ip_addresses:
            try:
                ip = ipaddress.ip_address(ip_str)

                # Block private IP ranges
                if ip.is_private:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Access to private IP ranges is forbidden: {ip_str}"
                    )

                # Block loopback addresses (127.0.0.0/8, ::1)
                if ip.is_loopback:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Access to loopback addresses is forbidden: {ip_str}"
                    )

                # Block link-local addresses (169.254.0.0/16, fe80::/10)
                # This includes AWS metadata endpoint 169.254.169.254
                if ip.is_link_local:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Access to link-local addresses is forbidden (AWS metadata endpoint blocked): {ip_str}"
                    )

                # Block multicast addresses
                if ip.is_multicast:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Access to multicast addresses is forbidden: {ip_str}"
                    )

                # Block reserved addresses
                if ip.is_reserved:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Access to reserved addresses is forbidden: {ip_str}"
                    )

            except ValueError:
                # Invalid IP address format
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid IP address format: {ip_str}"
                )

        log.info(f"✓ URL validation passed for: {hostname} -> {ip_addresses}")

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"URL validation error: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"URL validation failed: {str(e)}"
        )


def download_http(url: str) -> str:
    """
    Download file from HTTP/HTTPS URL.

    Args:
        url: HTTP or HTTPS URL to download

    Returns:
        Path to temporary file containing downloaded content

    Raises:
        HTTPException: If download fails or URL is blocked for security
    """
    log.info(f"Downloading from URL: {url[:100]}...")

    # SECURITY: Validate URL to prevent SSRF attacks
    validate_url_ssrf(url)

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
