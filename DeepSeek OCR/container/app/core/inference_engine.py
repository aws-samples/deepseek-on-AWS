"""
Inference Engine for DeepSeek OCR

This module handles OCR inference using the DeepSeek-OCR model.
It expects the model and tokenizer to be loaded externally and passed in.
"""

import time
import logging

from fastapi import HTTPException
from .config import get_config

log = logging.getLogger("deepseek-ocr-transformers")


def infer_single_image(model, tokenizer, image_path: str, prompt: str) -> str:
    """
    Run OCR inference on a single image.

    Args:
        model: Loaded DeepSeek-OCR model
        tokenizer: Loaded tokenizer
        image_path: Path to image file
        prompt: OCR prompt (e.g., "<image>\\nFree OCR.")

    Returns:
        OCR text result

    Raises:
        HTTPException: If model not loaded or inference fails
    """
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    # Load configuration for inference parameters
    cfg = get_config().model

    try:
        log.info(f"Running inference on: {image_path}")
        start_time = time.time()

        # Use model.infer() as per DeepSeek OCR documentation
        # eval_mode=True is required to return the text result
        result = model.infer(
            tokenizer,
            prompt=prompt,
            image_file=image_path,
            output_path='/tmp',
            base_size=cfg.base_size,
            image_size=cfg.image_size,
            crop_mode=cfg.crop_mode,
            test_compress=cfg.test_compress,
            save_results=False,
            eval_mode=True
        )

        elapsed = time.time() - start_time
        log.info(f"✓ Inference complete in {elapsed:.2f}s")

        return result

    except Exception as e:
        log.error(f"✗ Inference failed: {e}")
        import traceback
        log.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Inference failed: {str(e)}")
