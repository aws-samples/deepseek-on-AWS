"""
Thread-Safe Model Service for DeepSeek OCR

This module provides a thread-safe singleton for loading and accessing the
DeepSeek-OCR model. The singleton pattern ensures the model (8GB) is only
loaded once, even with concurrent requests.

Critical for async endpoint support where multiple coroutines may attempt
to access the model simultaneously.
"""

import os
import logging
import threading
from typing import Optional, Tuple

import torch

from .config import get_config

log = logging.getLogger("deepseek-ocr-transformers")


class ModelService:
    """
    Thread-safe singleton for DeepSeek-OCR model management.

    Uses double-checked locking pattern to ensure thread safety without
    unnecessary lock contention after initial load.

    Usage:
        service = ModelService()
        model, tokenizer = service.get_model()
    """

    _instance: Optional['ModelService'] = None
    _instance_lock = threading.RLock()

    def __new__(cls):
        """
        Ensure only one instance exists (singleton pattern).

        Uses double-checked locking for thread safety.
        """
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self):
        """
        Initialize the model service.

        Note: Due to singleton pattern, this may be called multiple times
        but initialization only happens once (checked via _initialized flag).
        """
        if self._initialized:
            return

        with self._instance_lock:
            if self._initialized:
                return

            # Model state
            self._model = None
            self._tokenizer = None
            self._model_loading_error: Optional[str] = None
            self._model_lock = threading.RLock()

            # Load configuration
            self._config = get_config()

            self._initialized = True
            log.info("ModelService initialized (singleton)")

    def get_model(self) -> Tuple[object, object]:
        """
        Get the loaded model and tokenizer.

        Loads the model on first call (lazy loading). Subsequent calls return
        the cached model without reloading.

        Returns:
            Tuple of (model, tokenizer)

        Raises:
            RuntimeError: If model loading failed

        Thread Safety:
            Uses double-checked locking to avoid race conditions while
            minimizing lock contention after initial load.
        """
        # Fast path: Model already loaded (no lock needed)
        if self._model is not None:
            return self._model, self._tokenizer

        # Slow path: Need to load model (acquire lock)
        with self._model_lock:
            # Double-check: Another thread may have loaded while we waited
            if self._model is not None:
                return self._model, self._tokenizer

            # Check if previous load attempt failed
            if self._model_loading_error is not None:
                raise RuntimeError(f"Model loading failed: {self._model_loading_error}")

            # Load model
            try:
                self._load_model()
            except Exception as e:
                self._model_loading_error = str(e)
                log.error(f"Model loading failed: {e}")
                raise RuntimeError(f"Model loading failed: {str(e)}") from e

            return self._model, self._tokenizer

    def _load_model(self):
        """
        Internal method to load the model.

        Must be called with _model_lock held.
        """
        from transformers import AutoModel, AutoTokenizer

        cfg = self._config.model

        log.info("=" * 80)
        log.info("LOADING DEEPSEEK OCR MODEL (Thread-Safe Singleton)")
        log.info("Model ID: %s", cfg.model_id)
        log.info("Device: %s | Dtype: %s", cfg.device, cfg.dtype)
        log.info("This may take 3-5 minutes...")
        log.info("=" * 80)

        # Load tokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(
            cfg.model_id,
            trust_remote_code=cfg.trust_remote_code
        )
        log.info("✓ Tokenizer loaded")

        # Load model
        self._model = AutoModel.from_pretrained(
            cfg.model_id,
            _attn_implementation=cfg.attn_implementation,
            trust_remote_code=cfg.trust_remote_code,
            use_safetensors=cfg.use_safetensors
        )

        # Move to device and set dtype
        dtype_map = {
            "bfloat16": torch.bfloat16,
            "float16": torch.float16,
            "float32": torch.float32,
        }

        if cfg.device == "cuda":
            self._model = self._model.eval().cuda().to(dtype_map[cfg.dtype])
            log.info("✓ Model loaded on GPU with %s", cfg.dtype)
        elif cfg.device == "cpu":
            self._model = self._model.eval().cpu().to(dtype_map[cfg.dtype])
            log.info("✓ Model loaded on CPU with %s", cfg.dtype)
        else:  # auto
            self._model = self._model.eval()
            if torch.cuda.is_available():
                self._model = self._model.cuda().to(dtype_map[cfg.dtype])
                log.info("✓ Model loaded on GPU (auto-detected) with %s", cfg.dtype)
            else:
                self._model = self._model.cpu().to(dtype_map[cfg.dtype])
                log.info("✓ Model loaded on CPU (auto-detected) with %s", cfg.dtype)

        log.info("=" * 80)
        log.info("✓ MODEL READY! (Thread-Safe)")
        log.info("=" * 80)

    def is_loaded(self) -> bool:
        """
        Check if model is loaded.

        Returns:
            True if model is loaded, False otherwise
        """
        return self._model is not None

    def get_error(self) -> Optional[str]:
        """
        Get the model loading error if any.

        Returns:
            Error message if loading failed, None otherwise
        """
        return self._model_loading_error

    @classmethod
    def reset_instance(cls):
        """
        Reset the singleton instance (for testing only).

        Warning: This should only be used in tests to reset state between
        test runs. Do NOT use in production code.
        """
        with cls._instance_lock:
            cls._instance = None
            log.warning("ModelService instance reset (testing only)")
