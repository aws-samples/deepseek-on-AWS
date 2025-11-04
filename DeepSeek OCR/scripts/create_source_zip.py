#!/usr/bin/env python3
"""Create source zip for CodeBuild without requiring zip command"""

import os
import zipfile
from pathlib import Path

def create_zip(source_dir, output_file, exclude_patterns):
    """Create zip file from source directory"""
    source_path = Path(source_dir).resolve()
    output_path = Path(output_file).resolve()

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source_path):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if not any(pattern in d for pattern in exclude_patterns)]

            for file in files:
                file_path = Path(root) / file
                # Skip excluded patterns
                if any(pattern in str(file_path) for pattern in exclude_patterns):
                    continue

                # Calculate relative path from source (this creates flat structure at root)
                arcname = file_path.relative_to(source_path)
                print(f"Adding: {arcname}")
                zipf.write(file_path, arcname)

    print(f"\n✅ Created {output_path.name} ({os.path.getsize(output_path) / 1024 / 1024:.2f} MB)")

if __name__ == "__main__":
    # Get script location and navigate to DeepSeek OCR directory
    script_dir = Path(__file__).parent
    deepseek_ocr_dir = script_dir.parent
    output_location = deepseek_ocr_dir.parent / "deepseek-ocr-source.zip"

    exclude = ['.ipynb_checkpoints', '__pycache__', '.git', '.DS_Store', '.gitignore']
    create_zip(deepseek_ocr_dir, output_location, exclude)
