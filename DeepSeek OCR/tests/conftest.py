"""
Shared pytest fixtures and configuration for DeepSeek OCR tests
"""

import pytest
import sys
import os
from pathlib import Path

# Add container app to Python path for imports
container_path = Path(__file__).parent.parent / "container" / "app"
sys.path.insert(0, str(container_path))


@pytest.fixture(scope="session")
def test_data_dir():
    """Fixture providing path to test data directory"""
    return Path(__file__).parent / "data"


@pytest.fixture
def sample_config():
    """Fixture providing sample configuration for testing"""
    from core.config import ServerConfig, ModelConfig, Config

    return Config(
        model=ModelConfig(),
        server=ServerConfig(max_request_size_mb=100),
        environment="dev",
        debug=True
    )


@pytest.fixture
def blocked_urls():
    """Fixture providing list of URLs that should be blocked by SSRF protection"""
    return [
        # AWS metadata endpoints
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/latest/meta-data/iam/security-credentials/",

        # Private IP ranges
        "http://10.0.0.1/internal",
        "http://172.16.0.1/admin",
        "http://192.168.1.1/config",

        # Loopback
        "http://127.0.0.1:8080/",
        "http://localhost/secret",
        "https://localhost:443/api",
    ]


@pytest.fixture
def allowed_urls():
    """Fixture providing list of legitimate public URLs that should be allowed"""
    return [
        "http://example.com/image.jpg",
        "https://example.com/document.pdf",
        "https://www.google.com/",
        "http://test.example.org/data",
    ]
