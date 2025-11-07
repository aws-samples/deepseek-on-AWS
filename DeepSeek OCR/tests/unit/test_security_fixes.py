"""
Unit tests for security fixes

Tests cover:
1. SSRF protection - blocking access to AWS metadata endpoint and private IPs
2. Input size validation - preventing DoS attacks via oversized requests
3. Configuration validation for security settings
"""

import pytest
from fastapi import HTTPException
import sys
import os

# Add container app to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../container/app'))

from core.input_adapters import validate_url_ssrf
from core.config import ServerConfig


class TestSSRFProtection:
    """Test SSRF (Server-Side Request Forgery) protection"""

    def test_blocks_aws_metadata_endpoint(self):
        """Verify AWS metadata endpoint 169.254.169.254 is blocked"""
        with pytest.raises(HTTPException) as exc_info:
            validate_url_ssrf("http://169.254.169.254/latest/meta-data/")

        assert exc_info.value.status_code == 403
        # May be caught as private IP or link-local, both are correct
        assert any(keyword in exc_info.value.detail.lower() for keyword in ["private", "link-local", "forbidden"])
        assert "169.254.169.254" in exc_info.value.detail

    def test_blocks_aws_metadata_endpoint_https(self):
        """Verify HTTPS access to metadata endpoint is also blocked"""
        with pytest.raises(HTTPException) as exc_info:
            validate_url_ssrf("https://169.254.169.254/latest/meta-data/iam/security-credentials/")

        assert exc_info.value.status_code == 403

    def test_blocks_private_ip_10_network(self):
        """Verify private IP range 10.0.0.0/8 is blocked"""
        with pytest.raises(HTTPException) as exc_info:
            validate_url_ssrf("http://10.0.0.1/internal")

        assert exc_info.value.status_code == 403
        assert "private" in exc_info.value.detail.lower()

    def test_blocks_private_ip_192_network(self):
        """Verify private IP range 192.168.0.0/16 is blocked"""
        with pytest.raises(HTTPException) as exc_info:
            validate_url_ssrf("http://192.168.1.1/admin")

        assert exc_info.value.status_code == 403
        assert "private" in exc_info.value.detail.lower()

    def test_blocks_private_ip_172_network(self):
        """Verify private IP range 172.16.0.0/12 is blocked"""
        with pytest.raises(HTTPException) as exc_info:
            validate_url_ssrf("http://172.16.0.1/config")

        assert exc_info.value.status_code == 403
        assert "private" in exc_info.value.detail.lower()

    def test_blocks_loopback_127(self):
        """Verify loopback address 127.0.0.1 is blocked"""
        with pytest.raises(HTTPException) as exc_info:
            validate_url_ssrf("http://127.0.0.1:8080/")

        assert exc_info.value.status_code == 403
        # May be caught as private IP or loopback, both are correct
        assert any(keyword in exc_info.value.detail.lower() for keyword in ["loopback", "private", "forbidden"])

    def test_blocks_localhost(self):
        """Verify localhost hostname is blocked"""
        with pytest.raises(HTTPException) as exc_info:
            validate_url_ssrf("http://localhost/secret")

        assert exc_info.value.status_code == 403
        # May be caught as private IP or loopback, both are correct
        assert any(keyword in exc_info.value.detail.lower() for keyword in ["loopback", "private", "forbidden"])

    def test_allows_public_http_url(self):
        """Verify legitimate public HTTP URLs are allowed"""
        # This should not raise an exception
        # Note: We're only testing validation, not actual HTTP requests
        try:
            validate_url_ssrf("http://example.com/image.jpg")
            # If we get here, validation passed (which is correct)
        except HTTPException as e:
            # Should not block public URLs
            if e.status_code == 403:
                pytest.fail(f"Public URL was incorrectly blocked: {e.detail}")

    def test_allows_public_https_url(self):
        """Verify legitimate public HTTPS URLs are allowed"""
        try:
            validate_url_ssrf("https://example.com/document.pdf")
        except HTTPException as e:
            if e.status_code == 403:
                pytest.fail(f"Public URL was incorrectly blocked: {e.detail}")

    def test_rejects_missing_hostname(self):
        """Verify URLs without hostname are rejected"""
        with pytest.raises(HTTPException) as exc_info:
            validate_url_ssrf("http:///path")

        assert exc_info.value.status_code == 400
        assert "hostname" in exc_info.value.detail.lower()

    def test_rejects_invalid_hostname(self):
        """Verify invalid hostnames are rejected"""
        with pytest.raises(HTTPException) as exc_info:
            validate_url_ssrf("http://invalid..hostname/path")

        assert exc_info.value.status_code == 400


class TestInputSizeValidation:
    """Test input size validation for DoS protection"""

    def test_default_max_request_size(self):
        """Verify default max request size is 100MB"""
        config = ServerConfig()
        assert config.max_request_size_mb == 100

    def test_max_request_size_validation(self):
        """Verify max_request_size_mb must be positive"""
        with pytest.raises(ValueError) as exc_info:
            ServerConfig(max_request_size_mb=0)

        assert "must be positive" in str(exc_info.value)

    def test_negative_max_request_size_rejected(self):
        """Verify negative max_request_size_mb is rejected"""
        with pytest.raises(ValueError):
            ServerConfig(max_request_size_mb=-1)

    def test_custom_max_request_size(self):
        """Verify custom max request size can be set"""
        config = ServerConfig(max_request_size_mb=50)
        assert config.max_request_size_mb == 50

    def test_large_max_request_size_allowed(self):
        """Verify large but reasonable size limits are allowed"""
        config = ServerConfig(max_request_size_mb=500)
        assert config.max_request_size_mb == 500


class TestSecurityConfiguration:
    """Test security-related configuration settings"""

    def test_server_config_includes_security_settings(self):
        """Verify ServerConfig includes security-related fields"""
        config = ServerConfig()

        # Check security-related attributes exist
        assert hasattr(config, 'max_request_size_mb')
        assert isinstance(config.max_request_size_mb, int)

    def test_server_config_validation_runs(self):
        """Verify ServerConfig __post_init__ validation executes"""
        # Should not raise
        config = ServerConfig()

        # Verify validation caught invalid values
        with pytest.raises(ValueError):
            ServerConfig(max_timeout=-1)

    def test_config_to_dict_includes_security(self):
        """Verify configuration dictionary includes security settings"""
        from core.config import Config

        config = Config.from_env()
        config_dict = config.to_dict()

        # Verify security settings are in the dict representation
        assert 'server' in config_dict
        assert 'max_request_size_mb' in config_dict['server']


class TestSecurityIntegration:
    """Integration tests for security features"""

    def test_ssrf_protection_with_various_schemes(self):
        """Test SSRF protection with different URL schemes"""
        blocked_urls = [
            "http://169.254.169.254/",
            "https://169.254.169.254/",
            "http://127.0.0.1/",
            "https://localhost/",
            "http://10.0.0.1/",
            "http://192.168.0.1/",
        ]

        for url in blocked_urls:
            with pytest.raises(HTTPException) as exc_info:
                validate_url_ssrf(url)
            assert exc_info.value.status_code == 403, f"URL {url} should be blocked"

    def test_ssrf_protection_error_messages(self):
        """Verify SSRF error messages are informative"""
        test_cases = [
            ("http://169.254.169.254/", ["private", "link-local", "forbidden"]),
            ("http://10.0.0.1/", ["private", "forbidden"]),
            ("http://127.0.0.1/", ["loopback", "private", "forbidden"]),
        ]

        for url, possible_keywords in test_cases:
            with pytest.raises(HTTPException) as exc_info:
                validate_url_ssrf(url)

            detail = exc_info.value.detail.lower()
            # At least one of the expected keywords should be present
            assert any(keyword in detail for keyword in possible_keywords), \
                f"Error message for {url} should mention one of {possible_keywords}, got: {detail}"


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
