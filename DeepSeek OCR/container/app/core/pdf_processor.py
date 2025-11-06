"""
PDF Processor for DeepSeek OCR

This module handles PDF to image conversion using pypdfium2.
Each page is rendered at specified DPI and saved as a JPEG image.
"""

import os
import tempfile
import logging
from typing import List

log = logging.getLogger("deepseek-ocr-transformers")


def pdf_to_images(pdf_path: str, dpi: int = 200) -> List[str]:
    """
    Convert PDF to list of image paths.

    Args:
        pdf_path: Path to PDF file
        dpi: Resolution for rendering (default: 200)

    Returns:
        List of paths to temporary image files (one per page)

    Note:
        Caller is responsible for cleaning up temporary files.
    """
    # Lazy import to avoid dependency issues in test environments
    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(pdf_path)
    image_paths = []

    for i in range(len(pdf)):
        page = pdf[i]
        pil = page.render(scale=dpi/72).to_pil()
        pil = pil.convert("RGB") if pil.mode != "RGB" else pil

        # Save to temp file
        fd, tmp = tempfile.mkstemp(suffix=f"_page{i}.jpg")
        with os.fdopen(fd, "wb") as f:
            pil.save(f, format="JPEG")
        image_paths.append(tmp)

    return image_paths
