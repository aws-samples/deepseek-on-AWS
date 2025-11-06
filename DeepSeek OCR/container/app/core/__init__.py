"""
Core Shared Components for DeepSeek OCR

This package contains shared, reusable components used by both
sync and async endpoints to avoid code duplication.

Modules:
- inference_engine: Core OCR inference logic
- pdf_processor: PDF to image conversion
- input_adapters: Input handling (HTTP, S3, base64)
- model_service: Thread-safe model management
- config: Configuration management
"""

__version__ = "1.0.0"

from .config import Config, get_config, reset_config

__all__ = ["Config", "get_config", "reset_config"]
