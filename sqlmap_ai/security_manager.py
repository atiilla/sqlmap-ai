import re
import time
import hashlib
import logging
import ipaddress
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import json
import threading
from functools import wraps
from cryptography.fernet import Fernet
import os


@dataclass
class SecurityConfig:
    
    max_requests_per_minute: int = 30
    max_requests_per_hour: int = 500
    max_concurrent_scans: int = 3
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    max_payload_length: int = 10000
    enable_audit_logging: bool = True
    require_confirmation: bool = True
    safe_mode: bool = True


@dataclass
class SecurityEvent:
    
    timestamp: datetime
    event_type: str
    severity: str
    details: Dict[str, Any]
    user_context: Optional[str] = None


class RateLimiter:
    
    
    def __init__(self, max_requests_per_minute: int = 30, max_requests_per_hour: int = 500):
        self.max_per_minute = max_requests_per_minute
        self.max_per_hour = max_requests_per_hour
        self.requests_minute = []
        self.requests_hour = []
        self.lock = threading.Lock()
    
    def is_allowed(self, identifier: str = "default") -> bool:
        
        now = datetime.now()
        
        with self.lock:
            # Clean old requests
            minute_cutoff = now - timedelta(minutes=1)
            hour_cutoff = now - timedelta(hours=1)
            
            self.requests_minute = [t for t in self.requests_minute if t > minute_cutoff]
            self.requests_hour = [t for t in self.requests_hour if t > hour_cutoff]
            
            # Check limits
            if len(self.requests_minute) >= self.max_per_minute:
                return False
            
            if len(self.requests_hour) >= self.max_per_hour:
                return False
            
            # Record request
            self.requests_minute.append(now)
            self.requests_hour.append(now)
            
            return True
    
    def get_reset_time(self) -> Tuple[int, int]:
        
        now = datetime.now()
        
        with self.lock:
            minute_reset = 60 if self.requests_minute else 0
            hour_reset = 3600 if self.requests_hour else 0
            
            if self.requests_minute:
                oldest_minute = min(self.requests_minute)
                minute_reset = max(0, 60 - (now - oldest_minute).seconds)
            
            if self.requests_hour:
                oldest_hour = min(self.requests_hour)
                hour_reset = max(0, 3600 - (now - oldest_hour).seconds)
            
            return minute_reset, hour_reset


class InputValidator:
    
    
    def __init__(self):
        self.dangerous_patterns = [
            r'[;|`]',   # Command injection (removed & as it's normal in URLs)
            r'\.\./',   # Path traversal
            r'<script', # XSS
            r'javascript:', # JavaScript protocol
            r'data:',   # Data URLs
            r'file:',   # File protocol
            r'ftp:',    # FTP protocol
        ]
        
        self.allowed_url_schemes = ['http', 'https']
        self.max_url_length = 2048
        self.max_parameter_length = 1000
    
    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        
        if not url or not isinstance(url, str):
            return False, "URL must be a non-empty string"
        
        if len(url) > self.max_url_length:
            return False, f"URL too long (max {self.max_url_length} characters)"
        
        # Check for dangerous patterns in the original URL first (before parsing)
        # This catches patterns that might be removed by URL parsing
        dangerous_patterns_original = [
            r'[;|`]',   # Command injection (excluding & which is normal in URLs)
            r'%3B',     # URL-encoded semicolon
            r'%7C',     # URL-encoded pipe
            r'%60',     # URL-encoded backtick
            r'\.\./',   # Path traversal
            r'<script', # XSS
            r'javascript:', # JavaScript protocol
            r'data:',   # Data URLs
            r'file:',   # File protocol
            r'ftp:',    # FTP protocol
        ]
        
        for pattern in dangerous_patterns_original:
            if re.search(pattern, url, re.IGNORECASE):
                return False, f"URL contains potentially dangerous pattern: {pattern}"
        
        # Parse URL to validate structure
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}"
        
        # Validate scheme
        if parsed.scheme.lower() not in self.allowed_url_schemes:
            return False, f"URL scheme '{parsed.scheme}' not allowed. Use {self.allowed_url_schemes}"
        
        # Validate hostname
        if not parsed.hostname:
            return False, "URL must include a hostname"
        
        # Check for localhost/private IPs in production
        if self._is_local_address(parsed.hostname):
            return False, "Local/private addresses are not allowed for security reasons"
        
        return True, None
    
    def _is_local_address(self, hostname: str) -> bool:
        
        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            # Not an IP address, check for localhost patterns
            local_patterns = [
                r'^localhost$',
                r'^127\.',
                r'^192\.168\.',
                r'^10\.',
                r'^172\.(1[6-9]|2[0-9]|3[01])\.',
                r'\.local$'
            ]
            
            for pattern in local_patterns:
                if re.match(pattern, hostname, re.IGNORECASE):
                    return True
        
        return False
    
    def validate_sqlmap_options(self, options: List[str]) -> Tuple[bool, Optional[str]]:
        
        dangerous_options = [
            '--os-shell',     # OS command execution
            '--os-pwn',       # OS takeover
            '--priv-esc',     # Privilege escalation
            '--file-write',   # File writing
            '--file-dest',    # File destination
            '--sql-shell',    # SQL shell
            '--crawl',        # Web crawling
            '--batch',        # Sometimes we allow this
        ]
        
        risky_options = [
            '--risk=3',       # High risk techniques
            '--level=5',      # Aggressive testing
            '--threads=',     # Resource usage
            '--time-sec=',    # Time delays
        ]
        
        for option in options:
            option_lower = option.lower()
            
            # Check dangerous options
            for dangerous in dangerous_options:
                if option_lower.startswith(dangerous.lower()):
                    if dangerous != '--batch':  # Allow batch mode
                        return False, f"Dangerous option not allowed: {option}"
            
            # Validate risky options
            for risky in risky_options:
                if option_lower.startswith(risky.lower()):
                    # Extract value and validate
                    try:
                        if risky.endswith('='):
                            value_part = option[len(risky):]
                            value = int(value_part)
                            
                            if risky == '--risk=' and value > 2:
                                return False, f"Risk level too high: {value} (max 2 allowed)"
                            elif risky == '--level=' and value > 3:
                                return False, f"Level too high: {value} (max 3 allowed)"
                            elif risky == '--threads=' and value > 10:
                                return False, f"Too many threads: {value} (max 10 allowed)"
                            elif risky == '--time-sec=' and value > 10:
                                return False, f"Time delay too long: {value} (max 10 seconds allowed)"
                    except ValueError:
                        return False, f"Invalid numeric value in option: {option}"
        
        return True, None
    
    def sanitize_filename(self, filename: str) -> str:
        
        # Remove dangerous characters
        sanitized = re.sub(r'[^\w\-_\.]', '_', filename)
        
        # Remove leading dots and dashes
        sanitized = re.sub(r'^[.-]+', '', sanitized)
        
        # Limit length
        if len(sanitized) > 255:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[:250] + ext
        
        # Ensure it's not empty
        if not sanitized:
            sanitized = "sqlmap_output"
        
        return sanitized


class AuditLogger:
    
    
    def __init__(self, log_file: str = None, config_manager=None):
        if log_file is None:
            # Use configuration if available, otherwise default
            if config_manager and hasattr(config_manager.config, 'logging'):
                logs_dir = Path.cwd() / config_manager.config.logging.log_directory
                log_file = logs_dir / config_manager.config.logging.audit_log_file
            else:
                # Default fallback
                logs_dir = Path.cwd() / "logs"
                log_file = logs_dir / "sqlmap_ai_audit.log"
            
            # Ensure logs directory exists
            logs_dir.mkdir(exist_ok=True)
        
        self.log_file = Path(log_file)
        self.logger = logging.getLogger("SQLMapAI_Audit")
        self.logger.setLevel(logging.INFO)
        
        # Create file handler
        handler = logging.FileHandler(self.log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # Create console handler for critical events
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def log_security_event(self, event: SecurityEvent):
        
        event_data = {
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "severity": event.severity,
            "details": event.details,
            "user_context": event.user_context
        }
        
        log_message = f"SECURITY_EVENT: {json.dumps(event_data)}"
        
        if event.severity == "CRITICAL":
            self.logger.critical(log_message)
        elif event.severity == "HIGH":
            self.logger.error(log_message)
        elif event.severity == "MEDIUM":
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def log_scan_start(self, target_url: str, options: List[str], user_context: str = None):
        
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type="SCAN_START",
            severity="INFO",
            details={
                "target_url": target_url,
                "options": options,
                "option_count": len(options)
            },
            user_context=user_context
        )
        self.log_security_event(event)
    
    def log_scan_result(self, target_url: str, vulnerabilities_found: int, user_context: str = None):
        
        severity = "HIGH" if vulnerabilities_found > 0 else "INFO"
        
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type="SCAN_COMPLETE",
            severity=severity,
            details={
                "target_url": target_url,
                "vulnerabilities_found": vulnerabilities_found
            },
            user_context=user_context
        )
        self.log_security_event(event)
    
    def log_security_violation(self, violation_type: str, details: Dict[str, Any], user_context: str = None):
        
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type="SECURITY_VIOLATION",
            severity="HIGH",
            details={
                "violation_type": violation_type,
                **details
            },
            user_context=user_context
        )
        self.log_security_event(event)


class EncryptionManager:
    
    
    def __init__(self):
        self.key = self._get_or_create_key()
        self.cipher = Fernet(self.key)
    
    def _get_or_create_key(self) -> bytes:
        
        key_file = Path(".sqlmap_ai_key")
        
        if key_file.exists():
            return key_file.read_bytes()
        else:
            key = Fernet.generate_key()
            key_file.write_bytes(key)
            key_file.chmod(0o600)  # Restrict permissions
            return key
    
    def encrypt_data(self, data: str) -> str:
        
        encrypted = self.cipher.encrypt(data.encode())
        return encrypted.hex()
    
    def decrypt_data(self, encrypted_hex: str) -> str:
        
        encrypted = bytes.fromhex(encrypted_hex)
        decrypted = self.cipher.decrypt(encrypted)
        return decrypted.decode()


class SecurityManager:
    
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.rate_limiter = RateLimiter(
            self.config.max_requests_per_minute,
            self.config.max_requests_per_hour
        )
        self.input_validator = InputValidator()
        self.audit_logger = AuditLogger() if self.config.enable_audit_logging else None
        self.encryption_manager = EncryptionManager()
        self.active_scans: Set[str] = set()
        self.scan_lock = threading.Lock()
    
    def validate_scan_request(self, target_url: str, options: List[str]) -> Tuple[bool, Optional[str]]:
        
        
        # Rate limiting check
        if not self.rate_limiter.is_allowed():
            minute_reset, hour_reset = self.rate_limiter.get_reset_time()
            if self.audit_logger:
                self.audit_logger.log_security_violation(
                    "RATE_LIMIT_EXCEEDED",
                    {"target_url": target_url, "reset_time_minutes": minute_reset}
                )
            return False, f"Rate limit exceeded. Try again in {minute_reset} seconds"
        
        # URL validation
        url_valid, url_error = self.input_validator.validate_url(target_url)
        if not url_valid:
            if self.audit_logger:
                self.audit_logger.log_security_violation(
                    "INVALID_URL",
                    {"target_url": target_url, "error": url_error}
                )
            return False, f"URL validation failed: {url_error}"
        
        # Options validation
        options_valid, options_error = self.input_validator.validate_sqlmap_options(options)
        if not options_valid:
            if self.audit_logger:
                self.audit_logger.log_security_violation(
                    "DANGEROUS_OPTIONS",
                    {"target_url": target_url, "options": options, "error": options_error}
                )
            return False, f"Options validation failed: {options_error}"
        
        # Concurrent scans check
        with self.scan_lock:
            if len(self.active_scans) >= self.config.max_concurrent_scans:
                return False, f"Maximum concurrent scans ({self.config.max_concurrent_scans}) reached"
        
        # Domain whitelist/blacklist check
        parsed_url = urllib.parse.urlparse(target_url)
        hostname = parsed_url.hostname
        
        if self.config.blocked_domains:
            for blocked in self.config.blocked_domains:
                if blocked in hostname:
                    if self.audit_logger:
                        self.audit_logger.log_security_violation(
                            "BLOCKED_DOMAIN",
                            {"target_url": target_url, "blocked_domain": blocked}
                        )
                    return False, f"Domain {hostname} is in blocked list"
        
        if self.config.allowed_domains:
            allowed = False
            for allowed_domain in self.config.allowed_domains:
                if allowed_domain in hostname:
                    allowed = True
                    break
            
            if not allowed:
                if self.audit_logger:
                    self.audit_logger.log_security_violation(
                        "DOMAIN_NOT_ALLOWED",
                        {"target_url": target_url, "hostname": hostname}
                    )
                return False, f"Domain {hostname} is not in allowed list"
        
        return True, None
    
    def register_scan_start(self, target_url: str, options: List[str], user_context: str = None) -> str:
        
        scan_id = hashlib.md5(f"{target_url}{time.time()}".encode()).hexdigest()
        
        with self.scan_lock:
            self.active_scans.add(scan_id)
        
        if self.audit_logger:
            self.audit_logger.log_scan_start(target_url, options, user_context)
        
        return scan_id
    
    def register_scan_complete(self, scan_id: str, target_url: str, vulnerabilities_found: int, user_context: str = None):
        
        with self.scan_lock:
            self.active_scans.discard(scan_id)
        
        if self.audit_logger:
            self.audit_logger.log_scan_result(target_url, vulnerabilities_found, user_context)
    
    def get_security_summary(self) -> Dict[str, Any]:
        
        minute_reset, hour_reset = self.rate_limiter.get_reset_time()
        
        return {
            "active_scans": len(self.active_scans),
            "max_concurrent_scans": self.config.max_concurrent_scans,
            "rate_limit_reset_minutes": minute_reset,
            "rate_limit_reset_hours": hour_reset,
            "safe_mode_enabled": self.config.safe_mode,
            "audit_logging_enabled": self.config.enable_audit_logging
        }


def require_security_check(security_manager: SecurityManager):
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract URL and options from function arguments
            target_url = None
            options = []
            
            # Try to find URL in args/kwargs
            for arg in args:
                if isinstance(arg, str) and (arg.startswith('http://') or arg.startswith('https://')):
                    target_url = arg
                    break
            
            if 'target_url' in kwargs:
                target_url = kwargs['target_url']
            
            if 'options' in kwargs:
                options = kwargs['options']
            
            # Perform security validation
            if target_url:
                valid, error = security_manager.validate_scan_request(target_url, options)
                if not valid:
                    raise SecurityError(f"Security validation failed: {error}")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


class SecurityError(Exception):
    
    pass


# Global security manager instance
default_security_config = SecurityConfig(
    max_requests_per_minute=30,
    max_requests_per_hour=500,
    max_concurrent_scans=3,
    enable_audit_logging=True,
    require_confirmation=True,
    safe_mode=True
)

security_manager = SecurityManager(default_security_config)
