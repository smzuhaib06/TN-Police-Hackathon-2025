"""
Error Handling and Validation Module
Comprehensive error handling for TOR Unveil application
"""

import logging
import traceback
from functools import wraps
from typing import Any, Callable, Dict, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tor_unveil_errors.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


class TORUnveilError(Exception):
    """Base exception for TOR Unveil"""
    def __init__(self, message: str, error_code: str = "GENERAL_ERROR"):
        self.message = message
        self.error_code = error_code
        self.timestamp = datetime.now().isoformat()
        super().__init__(self.message)


class PacketCaptureError(TORUnveilError):
    """Exception for packet capture operations"""
    def __init__(self, message: str):
        super().__init__(message, "PACKET_CAPTURE_ERROR")


class CorrelationError(TORUnveilError):
    """Exception for correlation operations"""
    def __init__(self, message: str):
        super().__init__(message, "CORRELATION_ERROR")


class TORScraperError(TORUnveilError):
    """Exception for TOR scraping operations"""
    def __init__(self, message: str):
        super().__init__(message, "TOR_SCRAPER_ERROR")


class PCAPAnalysisError(TORUnveilError):
    """Exception for PCAP analysis"""
    def __init__(self, message: str):
        super().__init__(message, "PCAP_ANALYSIS_ERROR")


class ValidationError(TORUnveilError):
    """Exception for validation failures"""
    def __init__(self, message: str):
        super().__init__(message, "VALIDATION_ERROR")


class ErrorHandler:
    """Global error handler and logger"""
    
    error_log = []
    
    @staticmethod
    def log_error(error: Exception, context: str = ""):
        """Log error with context"""
        error_entry = {
            'timestamp': datetime.now().isoformat(),
            'error_type': type(error).__name__,
            'message': str(error),
            'context': context,
            'traceback': traceback.format_exc()
        }
        
        ErrorHandler.error_log.append(error_entry)
        
        # Keep only last 100 errors
        if len(ErrorHandler.error_log) > 100:
            ErrorHandler.error_log = ErrorHandler.error_log[-100:]
        
        logger.error(
            f"Error in {context}: {type(error).__name__} - {str(error)}"
        )
    
    @staticmethod
    def get_error_log():
        """Get recent error log"""
        return ErrorHandler.error_log.copy()
    
    @staticmethod
    def clear_error_log():
        """Clear error log"""
        ErrorHandler.error_log = []


def handle_errors(error_code: str = "GENERAL_ERROR"):
    """Decorator for error handling"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except TORUnveilError as e:
                ErrorHandler.log_error(e, func.__name__)
                raise
            except Exception as e:
                ErrorHandler.log_error(e, func.__name__)
                raise TORUnveilError(str(e), error_code)
        return wrapper
    return decorator


class Validator:
    """Input validation utilities"""
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        import re
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        parts = ip.split('.')
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return 1 <= port <= 65535
    
    @staticmethod
    def validate_file_path(path: str) -> bool:
        """Validate file path"""
        import os
        try:
            return os.path.exists(path) and os.path.isfile(path)
        except Exception:
            return False
    
    @staticmethod
    def validate_interface(interface: str) -> bool:
        """Validate network interface"""
        try:
            from scapy.all import get_if_list
            return interface in get_if_list()
        except Exception:
            return False
    
    @staticmethod
    def validate_confidence_score(score: float) -> bool:
        """Validate confidence score"""
        return 0.0 <= score <= 1.0
    
    @staticmethod
    def validate_packet_count(count: int) -> bool:
        """Validate packet count"""
        return 1 <= count <= 1000000


class ResponseFormatter:
    """Format API responses consistently"""
    
    @staticmethod
    def success(data: Dict = None, message: str = "Success") -> Dict:
        """Format success response"""
        return {
            'status': 'success',
            'message': message,
            'data': data or {},
            'timestamp': datetime.now().isoformat()
        }
    
    @staticmethod
    def error(message: str, error_code: str = "ERROR", details: Dict = None) -> Dict:
        """Format error response"""
        return {
            'status': 'error',
            'message': message,
            'error_code': error_code,
            'details': details or {},
            'timestamp': datetime.now().isoformat()
        }
    
    @staticmethod
    def warning(message: str, data: Dict = None) -> Dict:
        """Format warning response"""
        return {
            'status': 'warning',
            'message': message,
            'data': data or {},
            'timestamp': datetime.now().isoformat()
        }


def validate_api_request(required_fields: list = None, optional_fields: list = None):
    """Decorator to validate API request data"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            from flask import request
            
            try:
                data = request.get_json() or {}
                
                # Check required fields
                if required_fields:
                    for field in required_fields:
                        if field not in data:
                            raise ValidationError(f"Missing required field: {field}")
                
                # Check optional fields types if needed
                if optional_fields:
                    for field in optional_fields:
                        if field in data and data[field] is None:
                            raise ValidationError(f"Invalid value for field: {field}")
                
                return func(*args, **kwargs)
            except ValidationError as e:
                ErrorHandler.log_error(e, func.__name__)
                return ResponseFormatter.error(
                    e.message,
                    e.error_code,
                    {'validation_error': True}
                ), 400
        return wrapper
    return decorator


def validate_parameter(param_name: str, validator_func: Callable):
    """Decorator to validate specific parameters"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            param_value = kwargs.get(param_name)
            
            if not validator_func(param_value):
                raise ValidationError(f"Invalid {param_name}: {param_value}")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Health check utilities
class HealthCheck:
    """System health status monitoring"""
    
    @staticmethod
    def check_packet_sniffer() -> Dict:
        """Check packet sniffer status"""
        try:
            from scapy.all import conf
            return {
                'status': 'healthy',
                'component': 'packet_sniffer',
                'message': 'Scapy available'
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'component': 'packet_sniffer',
                'message': str(e)
            }
    
    @staticmethod
    def check_ml_model() -> Dict:
        """Check ML model status"""
        try:
            from sklearn.cluster import DBSCAN
            return {
                'status': 'healthy',
                'component': 'ml_model',
                'message': 'scikit-learn available'
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'component': 'ml_model',
                'message': str(e)
            }
    
    @staticmethod
    def check_tor_scraper() -> Dict:
        """Check TOR scraper status"""
        try:
            import requests
            response = requests.get('https://onionoo.torproject.org/summary', timeout=5)
            return {
                'status': 'healthy' if response.status_code == 200 else 'degraded',
                'component': 'tor_scraper',
                'message': f'API response: {response.status_code}'
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'component': 'tor_scraper',
                'message': str(e)
            }
    
    @staticmethod
    def get_system_health() -> Dict:
        """Get overall system health"""
        return {
            'timestamp': datetime.now().isoformat(),
            'components': [
                HealthCheck.check_packet_sniffer(),
                HealthCheck.check_ml_model(),
                HealthCheck.check_tor_scraper()
            ]
        }


# Rate limiting
from collections import defaultdict
from datetime import timedelta

class RateLimiter:
    """Simple rate limiting"""
    
    def __init__(self, max_requests: int = 100, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(list)
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.time_window)
        
        # Clean old requests
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if req_time > cutoff
        ]
        
        # Check limit
        if len(self.requests[client_id]) >= self.max_requests:
            return False
        
        self.requests[client_id].append(now)
        return True


# Export commonly used items
__all__ = [
    'TORUnveilError',
    'PacketCaptureError',
    'CorrelationError',
    'TORScraperError',
    'PCAPAnalysisError',
    'ValidationError',
    'ErrorHandler',
    'Validator',
    'ResponseFormatter',
    'HealthCheck',
    'RateLimiter',
    'handle_errors',
    'validate_api_request',
    'validate_parameter'
]
