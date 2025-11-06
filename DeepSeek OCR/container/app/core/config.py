"""
Configuration Management for DeepSeek OCR

Centralized configuration with environment variable support, validation,
and type safety. Container provides sync endpoint only; async inference
is handled by SageMaker AsyncInferenceConfig.

Environment Variables:
    MODEL_ID: HuggingFace model ID (default: deepseek-ai/DeepSeek-OCR)
    DEFAULT_PROMPT: Default OCR prompt
    DEVICE: Compute device (cuda, cpu, auto)
    DTYPE: Model dtype (bfloat16, float16, float32)
    MAX_TIMEOUT: Maximum processing timeout in seconds
    AWS_REGION: AWS region for S3 downloads
    ENVIRONMENT: Deployment environment (dev, staging, prod)
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Literal
from pathlib import Path

log = logging.getLogger("deepseek-ocr-transformers")


@dataclass
class ModelConfig:
    """Model-related configuration"""

    model_id: str = "deepseek-ai/DeepSeek-OCR"
    trust_remote_code: bool = True
    use_safetensors: bool = True
    attn_implementation: str = "flash_attention_2"

    # Inference settings
    device: Literal["cuda", "cpu", "auto"] = "cuda"
    dtype: Literal["bfloat16", "float16", "float32"] = "bfloat16"

    # Image processing
    base_size: int = 1024
    image_size: int = 640
    crop_mode: bool = True
    test_compress: bool = False

    def __post_init__(self):
        """Validate model configuration"""
        if self.device not in ["cuda", "cpu", "auto"]:
            raise ValueError(f"Invalid device: {self.device}. Must be cuda, cpu, or auto")
        if self.dtype not in ["bfloat16", "float16", "float32"]:
            raise ValueError(f"Invalid dtype: {self.dtype}")
        if self.base_size <= 0 or self.image_size <= 0:
            raise ValueError("Image sizes must be positive integers")


@dataclass
class ServerConfig:
    """Server and endpoint configuration"""

    # Prompts
    default_prompt: str = "<image>\n<|grounding|>Convert the document to markdown."

    # Timeouts (in seconds)
    max_timeout: int = 60  # Sync endpoint timeout
    startup_timeout: int = 300  # Model loading timeout (5 min)

    # Server settings
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 1  # Single worker for model singleton

    # Rate limiting
    max_concurrent_requests: int = 10

    def __post_init__(self):
        """Validate server configuration"""
        if self.max_timeout <= 0:
            raise ValueError("max_timeout must be positive")
        if self.port < 1 or self.port > 65535:
            raise ValueError("Invalid port number")
        if self.workers < 1:
            raise ValueError("workers must be >= 1")


@dataclass
class AWSConfig:
    """AWS-specific configuration"""

    region: str = "us-east-1"

    # S3 for downloads (input adapters)
    s3_download_timeout: int = 300  # 5 minutes for large files

    def __post_init__(self):
        """Validate AWS configuration"""
        if self.s3_download_timeout < 1:
            raise ValueError("s3_download_timeout must be positive")


@dataclass
class Config:
    """
    Main configuration object combining all settings.

    Loads configuration from environment variables with sensible defaults.
    Validates all settings on initialization.
    """

    # Sub-configurations
    model: ModelConfig = field(default_factory=ModelConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    aws: AWSConfig = field(default_factory=AWSConfig)

    # Environment
    environment: Literal["dev", "staging", "prod"] = "prod"
    debug: bool = False

    def __post_init__(self):
        """Validate overall configuration"""
        if self.environment not in ["dev", "staging", "prod"]:
            raise ValueError(f"Invalid environment: {self.environment}")

    @classmethod
    def from_env(cls) -> "Config":
        """
        Load configuration from environment variables.

        Returns:
            Validated Config object

        Raises:
            ValueError: If configuration is invalid
        """
        # Model configuration
        model_config = ModelConfig(
            model_id=os.getenv("MODEL_ID", "deepseek-ai/DeepSeek-OCR"),
            device=os.getenv("DEVICE", "cuda"),
            dtype=os.getenv("DTYPE", "bfloat16"),
            base_size=int(os.getenv("BASE_SIZE", "1024")),
            image_size=int(os.getenv("IMAGE_SIZE", "640")),
            crop_mode=os.getenv("CROP_MODE", "true").lower() == "true",
            test_compress=os.getenv("TEST_COMPRESS", "false").lower() == "true",
        )

        # Server configuration
        server_config = ServerConfig(
            default_prompt=os.getenv(
                "DEFAULT_PROMPT",
                "<image>\n<|grounding|>Convert the document to markdown."
            ),
            max_timeout=int(os.getenv("MAX_TIMEOUT", "60")),
            startup_timeout=int(os.getenv("STARTUP_TIMEOUT", "300")),
            host=os.getenv("HOST", "0.0.0.0"),
            port=int(os.getenv("PORT", "8080")),
            workers=int(os.getenv("WORKERS", "1")),
            max_concurrent_requests=int(os.getenv("MAX_CONCURRENT_REQUESTS", "10")),
        )

        # AWS configuration
        aws_config = AWSConfig(
            region=os.getenv("AWS_REGION", "us-east-1"),
            s3_download_timeout=int(os.getenv("S3_DOWNLOAD_TIMEOUT", "300")),
        )

        # Environment settings
        environment = os.getenv("ENVIRONMENT", "prod")
        debug = os.getenv("DEBUG", "false").lower() == "true"

        config = cls(
            model=model_config,
            server=server_config,
            aws=aws_config,
            environment=environment,
            debug=debug,
        )

        log.info("Configuration loaded from environment:")
        log.info(f"  Environment: {config.environment}")
        log.info(f"  Model ID: {config.model.model_id}")
        log.info(f"  Device: {config.model.device}")
        log.info(f"  Max Timeout: {config.server.max_timeout}s")

        return config

    def validate(self) -> None:
        """
        Validate configuration for specific deployment scenarios.

        Raises:
            ValueError: If configuration is invalid for the scenario
        """
        # Production validation
        if self.environment == "prod":
            if self.debug:
                log.warning("Debug mode enabled in production!")

            if self.model.device == "cpu":
                log.warning("Using CPU in production - performance will be poor")

    def to_dict(self) -> dict:
        """
        Convert configuration to dictionary for logging/debugging.

        Returns:
            Dictionary representation of config
        """
        return {
            "environment": self.environment,
            "debug": self.debug,
            "model": {
                "model_id": self.model.model_id,
                "device": self.model.device,
                "dtype": self.model.dtype,
            },
            "server": {
                "max_timeout": self.server.max_timeout,
                "port": self.server.port,
                "workers": self.server.workers,
            },
            "aws": {
                "region": self.aws.region,
                "s3_download_timeout": self.aws.s3_download_timeout,
            }
        }


# Global configuration instance (singleton)
_config: Optional[Config] = None


def get_config() -> Config:
    """
    Get the global configuration instance.

    Loads from environment on first call, then returns cached instance.

    Returns:
        Config: Global configuration object
    """
    global _config
    if _config is None:
        _config = Config.from_env()
        _config.validate()
    return _config


def reset_config() -> None:
    """
    Reset the global configuration (for testing only).

    Warning: This should only be used in tests to reset state between
    test runs. Do NOT use in production code.
    """
    global _config
    _config = None
    log.warning("Configuration reset (testing only)")
