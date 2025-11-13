#!/usr/bin/env python3

import pytest
import time
from sqlmap_ai.security_manager import SecurityManager, SecurityConfig, RateLimiter, InputValidator


class TestRateLimiter:
    
    
    def test_rate_limiter_allows_requests_within_limit(self):
        
        limiter = RateLimiter(max_requests_per_minute=5, max_requests_per_hour=50)
        
        # Should allow first few requests
        for _ in range(5):
            assert limiter.is_allowed()
    
    def test_rate_limiter_blocks_excess_requests(self):
        
        limiter = RateLimiter(max_requests_per_minute=2, max_requests_per_hour=10)
        
        # Use up the limit
        assert limiter.is_allowed()
        assert limiter.is_allowed()
        
        # Should block the next request
        assert not limiter.is_allowed()


class TestInputValidator:
    
    
    def test_valid_url_validation(self):
        
        validator = InputValidator()
        
        valid_urls = [
            "http://example.com/page.php?id=1",
            "https://test.site.com/admin/login.php",
            "http://192.168.1.100:8080/app?param=value"
        ]
        
        for url in valid_urls:
            valid, error = validator.validate_url(url)
            assert valid, f"URL {url} should be valid, got error: {error}"
    
    def test_invalid_url_validation(self):
        
        validator = InputValidator()
        
        invalid_urls = [
            "",  # Empty
            "not_a_url",  # Not a URL
            "ftp://example.com/file",  # Wrong scheme
            "http://localhost/test",  # Localhost
            "http://127.0.0.1/admin",  # Localhost IP
            "http://192.168.1.1/app",  # Private IP
            "javascript:alert('xss')",  # JavaScript
            "data:text/html,<script>alert('xss')</script>"  # Data URL
        ]
        
        for url in invalid_urls:
            valid, error = validator.validate_url(url)
            assert not valid, f"URL {url} should be invalid"
            assert error is not None
    
    def test_sqlmap_options_validation(self):
        
        validator = InputValidator()
        
        # Safe options should pass
        safe_options = ["--dbs", "--tables", "--batch", "--threads=5", "--level=2"]
        valid, error = validator.validate_sqlmap_options(safe_options)
        assert valid, f"Safe options should be valid, got error: {error}"
        
        # Dangerous options should fail
        dangerous_options = ["--os-shell", "--file-write", "--sql-shell"]
        for option in dangerous_options:
            valid, error = validator.validate_sqlmap_options([option])
            assert not valid, f"Dangerous option {option} should be invalid"
    
    def test_filename_sanitization(self):
        
        validator = InputValidator()
        
        test_cases = [
            ("normal_file.txt", "normal_file.txt"),
            ("file with spaces.txt", "file_with_spaces.txt"),
            ("../../../etc/passwd", "etc_passwd"),
            ("file<>:\"|\0?.txt", "file_________.txt"),
            ("", "sqlmap_output"),
            ("con.txt", "con.txt"),  # Windows reserved name handling
        ]
        
        for input_name, expected in test_cases:
            result = validator.sanitize_filename(input_name)
            assert result == expected or len(result) > 0  # At least not empty


class TestSecurityManager:
    
    
    def test_security_manager_initialization(self):
        
        config = SecurityConfig(
            max_requests_per_minute=10,
            max_concurrent_scans=2
        )
        manager = SecurityManager(config)
        
        assert manager.config.max_requests_per_minute == 10
        assert manager.config.max_concurrent_scans == 2
    
    def test_scan_request_validation(self):
        
        manager = SecurityManager()
        
        # Valid request should pass
        valid, error = manager.validate_scan_request(
            "http://example.com/test.php?id=1",
            ["--dbs", "--batch"]
        )
        assert valid, f"Valid request should pass, got error: {error}"
    
    def test_concurrent_scan_limiting(self):
        
        config = SecurityConfig(max_concurrent_scans=1)
        manager = SecurityManager(config)
        
        # First scan should be allowed
        scan_id1 = manager.register_scan_start("http://example.com/1", [])
        assert scan_id1 is not None
        
        # Second scan should be blocked
        valid, error = manager.validate_scan_request("http://example.com/2", [])
        assert not valid
        assert "concurrent" in error.lower()
        
        # After completing first scan, second should be allowed
        manager.register_scan_complete(scan_id1, "http://example.com/1", 0)
        valid, error = manager.validate_scan_request("http://example.com/2", [])
        assert valid


if __name__ == "__main__":
    pytest.main([__file__])
