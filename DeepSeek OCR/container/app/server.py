import os
import base64
import logging
import time
import threading
from typing import Optional

import torch
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel

# Import shared core modules
# Support both relative (Docker runtime) and absolute (testing) imports
try:
    from .core import input_adapters, pdf_processor, inference_engine
    from .core.model_service import ModelService
    from .core.config import get_config
except ImportError:
    from core import input_adapters, pdf_processor, inference_engine
    from core.model_service import ModelService
    from core.config import get_config

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("deepseek-ocr-transformers")

# Load configuration
config = get_config()
MODEL_ID = config.model.model_id
DEFAULT_PROMPT = config.server.default_prompt

# Thread-safe model service (singleton)
_model_service = ModelService()
_startup_time = None

# Backward compatibility: Keep global references for existing code
_model = None
_tokenizer = None
_model_loading_error = None

def load_model():
    """
    Load DeepSeek OCR model using Transformers (thread-safe).

    This now delegates to ModelService for thread safety.
    Kept for backward compatibility with startup code.
    """
    global _model, _tokenizer, _model_loading_error

    if _model is not None:
        log.info("Model already loaded, skipping...")
        return

    try:
        # Delegate to thread-safe ModelService
        _model, _tokenizer = _model_service.get_model()
    except Exception as e:
        _model_loading_error = str(e)
        log.error("=" * 80)
        log.error("✗ FATAL ERROR: Failed to load model")
        log.error("Error: %s", e)
        log.error("=" * 80)
        import traceback
        log.error(traceback.format_exc())
        raise

# Backward compatibility: Keep old function names as aliases to shared modules
_download_http = input_adapters.download_http
_download_s3 = input_adapters.download_s3
_bytes_to_tempfile = input_adapters.bytes_to_tempfile
_image_to_path = input_adapters.image_to_path
_pdf_to_images = pdf_processor.pdf_to_images


def infer_single_image(image_path: str, prompt: str) -> str:
    """
    Run inference on a single image using Transformers (thread-safe).

    This wrapper gets the model from the thread-safe ModelService and passes it
    to the shared inference engine.
    """
    # Get model from thread-safe service
    model, tokenizer = _model_service.get_model()
    return inference_engine.infer_single_image(model, tokenizer, image_path, prompt)

# FastAPI app
app = FastAPI(title="DeepSeek OCR Transformers SageMaker BYOC", version="1.0.0")

class OCRRequest(BaseModel):
    prompt: Optional[str] = None
    image_url: Optional[str] = None
    image_base64: Optional[str] = None
    pdf_url: Optional[str] = None
    pdf_base64: Optional[str] = None

@app.on_event("startup")
async def startup_event():
    """Load model in background on startup"""
    global _startup_time
    _startup_time = time.time()

    log.info("=" * 80)
    log.info("CONTAINER STARTUP - DeepSeek OCR with Transformers")
    log.info("Model: %s", MODEL_ID)
    log.info("=" * 80)

    # Load model in background thread
    def load_model_background():
        try:
            load_model()
            elapsed = time.time() - _startup_time
            log.info(f"✓ Container ready (startup: {elapsed:.1f}s)")
        except Exception as e:
            log.error(f"✗ Model loading failed: {e}")

    thread = threading.Thread(target=load_model_background, daemon=True)
    thread.start()

@app.get("/ping")
def ping():
    """SageMaker health check (thread-safe)"""
    if not _model_service.is_loaded():
        error = _model_service.get_error()
        if error:
            log.error(f"/ping - Model failed to load: {error}")
            raise HTTPException(status_code=503, detail=f"Model failed: {error}")
        else:
            log.warning("/ping - Model still loading...")
            raise HTTPException(status_code=503, detail="Model loading")

    return {"status": "healthy", "model": MODEL_ID, "backend": "transformers"}

@app.get("/health")
def health():
    """Detailed health check (thread-safe)"""
    uptime = time.time() - _startup_time if _startup_time else 0
    is_loaded = _model_service.is_loaded()
    return {
        "status": "healthy" if is_loaded else "loading",
        "model_loaded": is_loaded,
        "model_id": MODEL_ID,
        "backend": "transformers",
        "uptime_seconds": round(uptime, 1),
        "error": _model_service.get_error()
    }

@app.post("/invocations")
async def invocations(req: Request):
    """
    SageMaker inference endpoint (thread-safe)

    Supports two input formats:
    1. JSON: {"image_base64": "...", "pdf_base64": "...", "prompt": "..."}
    2. Raw binary: Direct image/PDF bytes (with Content-Type header)
    """
    if not _model_service.is_loaded():
        log.error("/invocations called but model not loaded!")
        error = _model_service.get_error()
        if error:
            raise HTTPException(status_code=503, detail=f"Model failed: {error}")
        raise HTTPException(status_code=503, detail="Model not ready")

    # Get content type from header
    content_type = req.headers.get('content-type', '').lower()

    # Try to parse as JSON first
    try:
        body = await req.json()
        is_json = True
    except Exception as e:
        # If Content-Type is application/json but parsing failed, return 400
        if 'application/json' in content_type:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

        # Not JSON and not claiming to be - treat as raw binary data
        is_json = False
        raw_data = await req.body()
        log.info(f"Received raw binary data ({len(raw_data)} bytes), Content-Type: {content_type}")

        # Detect if PDF or image based on content type or magic bytes
        is_pdf = False
        if 'pdf' in content_type or raw_data.startswith(b'%PDF'):
            is_pdf = True

        # Convert to JSON format expected by the rest of the code
        body = {
            "prompt": DEFAULT_PROMPT,
            "pdf_base64" if is_pdf else "image_base64": base64.b64encode(raw_data).decode('utf-8')
        }
        log.info(f"Converted raw {'PDF' if is_pdf else 'image'} to JSON format")

    o = OCRRequest(**body)
    prompt = o.prompt or DEFAULT_PROMPT

    # Handle single image
    if o.image_url or o.image_base64:
        if o.image_url:
            image_path = _image_to_path(o.image_url)
        else:
            image_path = _image_to_path(base64.b64decode(o.image_base64))

        text = infer_single_image(image_path, prompt)

        # Cleanup temp file
        try:
            os.unlink(image_path)
        except:
            pass

        return {"text": text}

    # Handle PDF
    if o.pdf_url or o.pdf_base64:
        if o.pdf_url:
            if o.pdf_url.startswith(("http://", "https://")):
                pdf_path = _download_http(o.pdf_url)
            else:
                pdf_path = _download_s3(o.pdf_url)
        else:
            pdf_path = _bytes_to_tempfile(base64.b64decode(o.pdf_base64), suffix=".pdf")

        # Convert PDF to images
        log.info("Converting PDF to images...")
        image_paths = _pdf_to_images(pdf_path)
        log.info(f"✓ PDF converted to {len(image_paths)} pages")

        # Process each page
        results = []
        for idx, img_path in enumerate(image_paths, start=1):
            log.info(f"Processing page {idx}/{len(image_paths)}...")
            text = infer_single_image(img_path, prompt)
            results.append(f"\n\n## Page {idx}\n\n{text}")

            # Cleanup page image
            try:
                os.unlink(img_path)
            except:
                pass

        # Cleanup PDF
        try:
            os.unlink(pdf_path)
        except:
            pass

        return {"text": "".join(results), "pages": len(image_paths)}

    raise HTTPException(status_code=400, detail="Provide image_url/base64 or pdf_url/base64")
