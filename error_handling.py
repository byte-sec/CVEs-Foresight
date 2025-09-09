# error_handling.py
import logging
import traceback
import functools
from typing import Any, Callable, Dict, Optional, Union, Tuple
from datetime import datetime
import threading
from enum import Enum

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Error categories for better classification"""
    NETWORK = "network"
    DATABASE = "database"
    API = "api"
    VALIDATION = "validation"
    CONFIGURATION = "configuration"
    GUI = "gui"
    THREADING = "threading"
    IO = "io"
    UNKNOWN = "unknown"

class CVEAppError(Exception):
    """Base exception class for CVE application errors"""
    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.UNKNOWN, 
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM, 
                 details: Dict[str, Any] = None, cause: Exception = None):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.details = details or {}
        self.cause = cause
        self.timestamp = datetime.now()
        self.thread_id = threading.get_ident()

class NetworkError(CVEAppError):
    """Network-related errors"""
    def __init__(self, message: str, status_code: Optional[int] = None, 
                 url: Optional[str] = None, **kwargs):
        super().__init__(message, category=ErrorCategory.NETWORK, **kwargs)
        self.status_code = status_code
        self.url = url
        if status_code:
            self.details['status_code'] = status_code
        if url:
            self.details['url'] = url

class DatabaseError(CVEAppError):
    """Database-related errors"""
    def __init__(self, message: str, query: Optional[str] = None, **kwargs):
        super().__init__(message, category=ErrorCategory.DATABASE, **kwargs)
        self.query = query
        if query:
            self.details['query'] = query[:200]  # Truncate long queries

class APIError(CVEAppError):
    """API-related errors"""
    def __init__(self, message: str, api_name: Optional[str] = None, 
                 endpoint: Optional[str] = None, response_data: Optional[str] = None, **kwargs):
        super().__init__(message, category=ErrorCategory.API, **kwargs)
        self.api_name = api_name
        self.endpoint = endpoint
        self.response_data = response_data
        if api_name:
            self.details['api_name'] = api_name
        if endpoint:
            self.details['endpoint'] = endpoint
        if response_data:
            self.details['response_data'] = response_data[:500]  # Truncate long responses

class ValidationError(CVEAppError):
    """Validation-related errors"""
    def __init__(self, message: str, field_name: Optional[str] = None, 
                 field_value: Optional[str] = None, **kwargs):
        super().__init__(message, category=ErrorCategory.VALIDATION, **kwargs)
        self.field_name = field_name
        self.field_value = field_value
        if field_name:
            self.details['field_name'] = field_name
        if field_value:
            self.details['field_value'] = str(field_value)[:100]  # Truncate long values

class ConfigurationError(CVEAppError):
    """Configuration-related errors"""
    def __init__(self, message: str, config_key: Optional[str] = None, **kwargs):
        super().__init__(message, category=ErrorCategory.CONFIGURATION, **kwargs)
        self.config_key = config_key
        if config_key:
            self.details['config_key'] = config_key

class ErrorTracker:
    """Centralized error tracking and reporting"""
    
    def __init__(self):
        self.error_counts = {}
        self.recent_errors = []
        self.max_recent_errors = 100
        self._lock = threading.RLock()
    
    def track_error(self, error: Union[CVEAppError, Exception], context: str = ""):
        """Track an error occurrence"""
        with self._lock:
            # Create error info
            if isinstance(error, CVEAppError):
                error_info = {
                    'timestamp': error.timestamp,
                    'message': error.message,
                    'category': error.category.value,
                    'severity': error.severity.value,
                    'details': error.details,
                    'context': context,
                    'thread_id': error.thread_id
                }
                error_key = f"{error.category.value}:{error.__class__.__name__}"
            else:
                error_info = {
                    'timestamp': datetime.now(),
                    'message': str(error),
                    'category': ErrorCategory.UNKNOWN.value,
                    'severity': ErrorSeverity.MEDIUM.value,
                    'details': {'type': type(error).__name__},
                    'context': context,
                    'thread_id': threading.get_ident()
                }
                error_key = f"unknown:{type(error).__name__}"
            
            # Track error counts
            self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
            
            # Add to recent errors
            self.recent_errors.append(error_info)
            if len(self.recent_errors) > self.max_recent_errors:
                self.recent_errors.pop(0)
            
            # Log the error
            self._log_error(error_info)
    
    def _log_error(self, error_info: Dict[str, Any]):
        """Log error with appropriate level"""
        severity = error_info['severity']
        message = f"[{error_info['category'].upper()}] {error_info['message']}"
        
        if error_info['context']:
            message += f" (Context: {error_info['context']})"
        
        if error_info['details']:
            details_str = ", ".join(f"{k}={v}" for k, v in error_info['details'].items())
            message += f" [Details: {details_str}]"
        
        if severity == ErrorSeverity.CRITICAL.value:
            logger.critical(message)
        elif severity == ErrorSeverity.HIGH.value:
            logger.error(message)
        elif severity == ErrorSeverity.MEDIUM.value:
            logger.warning(message)
        else:
            logger.info(message)
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get a summary of tracked errors"""
        with self._lock:
            total_errors = sum(self.error_counts.values())
            categories = {}
            severities = {}
            
            for error_info in self.recent_errors:
                category = error_info['category']
                severity = error_info['severity']
                categories[category] = categories.get(category, 0) + 1
                severities[severity] = severities.get(severity, 0) + 1
            
            return {
                'total_errors': total_errors,
                'unique_error_types': len(self.error_counts),
                'recent_errors_count': len(self.recent_errors),
                'categories': categories,
                'severities': severities,
                'most_common_errors': sorted(
                    self.error_counts.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:5]
            }
    
    def get_recent_errors(self, count: int = 10) -> list:
        """Get recent errors"""
        with self._lock:
            return self.recent_errors[-count:] if self.recent_errors else []
    
    def clear_errors(self):
        """Clear error tracking data"""
        with self._lock:
            self.error_counts.clear()
            self.recent_errors.clear()
            logger.info("Error tracking data cleared")

# Global error tracker instance
error_tracker = ErrorTracker()

def handle_exception(category: ErrorCategory = ErrorCategory.UNKNOWN, 
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    reraise: bool = True, 
                    default_return: Any = None,
                    context: str = ""):
    """
    Decorator for consistent exception handling
    
    Args:
        category: Error category
        severity: Error severity
        reraise: Whether to reraise the exception
        default_return: Value to return if exception is caught
        context: Additional context information
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except CVEAppError as e:
                # Track the error
                error_tracker.track_error(e, context or func.__name__)
                
                if reraise:
                    raise
                return default_return
            except Exception as e:
                # Wrap generic exceptions in CVEAppError
                wrapped_error = CVEAppError(
                    message=f"Unexpected error in {func.__name__}: {str(e)}",
                    category=category,
                    severity=severity,
                    cause=e
                )
                
                error_tracker.track_error(wrapped_error, context or func.__name__)
                
                if reraise:
                    raise wrapped_error from e
                return default_return
        return wrapper
    return decorator

def safe_execute(func: Callable, *args, default_return: Any = None, 
                context: str = "", log_errors: bool = True, **kwargs) -> Tuple[Any, Optional[Exception]]:
    """
    Safely execute a function and return result with any exception
    
    Args:
        func: Function to execute
        *args: Positional arguments for the function
        default_return: Value to return if function fails
        context: Context information for error tracking
        log_errors: Whether to log errors
        **kwargs: Keyword arguments for the function
    
    Returns:
        Tuple of (result, exception) where exception is None if successful
    """
    try:
        result = func(*args, **kwargs)
        return result, None
    except Exception as e:
        if log_errors:
            error_tracker.track_error(e, context or func.__name__)
        return default_return, e

def create_error_response(message: str, error_code: str = "UNKNOWN_ERROR", 
                         details: Dict[str, Any] = None) -> Dict[str, Any]:
    """Create a standardized error response"""
    return {
        'success': False,
        'error': True,
        'error_code': error_code,
        'message': message,
        'details': details or {},
        'timestamp': datetime.now().isoformat()
    }

def create_success_response(data: Any = None, message: str = "Operation successful") -> Dict[str, Any]:
    """Create a standardized success response"""
    return {
        'success': True,
        'error': False,
        'message': message,
        'data': data,
        'timestamp': datetime.now().isoformat()
    }

def log_and_handle_error(error: Exception, context: str = "", 
                        severity: ErrorSeverity = ErrorSeverity.MEDIUM) -> Dict[str, Any]:
    """Log an error and return a standardized error response"""
    if isinstance(error, CVEAppError):
        error_tracker.track_error(error, context)
        return create_error_response(
            message=error.message,
            error_code=f"{error.category.value.upper()}_ERROR",
            details=error.details
        )
    else:
        wrapped_error = CVEAppError(
            message=str(error),
            category=ErrorCategory.UNKNOWN,
            severity=severity,
            cause=error
        )
        error_tracker.track_error(wrapped_error, context)
        return create_error_response(
            message=str(error),
            error_code="UNKNOWN_ERROR",
            details={'type': type(error).__name__}
        )

def get_error_details_for_user(error: Exception) -> str:
    """Get user-friendly error message"""
    if isinstance(error, NetworkError):
        if error.status_code == 429:
            return "Rate limit exceeded. Please wait a moment and try again."
        elif error.status_code == 401:
            return "Authentication failed. Please check your API key."
        elif error.status_code == 403:
            return "Access denied. Please verify your API permissions."
        elif error.status_code >= 500:
            return "Service temporarily unavailable. Please try again later."
        else:
            return "Network error occurred. Please check your connection."
    
    elif isinstance(error, DatabaseError):
        return "Database operation failed. Please try again or contact support."
    
    elif isinstance(error, ValidationError):
        return f"Invalid input: {error.message}"
    
    elif isinstance(error, ConfigurationError):
        return f"Configuration error: {error.message}"
    
    elif isinstance(error, APIError):
        return f"API error: {error.message}"
    
    else:
        return "An unexpected error occurred. Please try again."

def retry_on_failure(max_retries: int = 3, delay: float = 1.0, 
                    backoff_factor: float = 2.0,
                    retry_on: Tuple[type, ...] = (NetworkError, APIError)):
    """
    Decorator to retry function on specific exceptions
    
    Args:
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff_factor: Factor to multiply delay by for exponential backoff
        retry_on: Tuple of exception types to retry on
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retry_on as e:
                    last_exception = e
                    if attempt < max_retries:
                        logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. "
                                     f"Retrying in {current_delay}s...")
                        import time
                        time.sleep(current_delay)
                        current_delay *= backoff_factor
                    else:
                        logger.error(f"All {max_retries + 1} attempts failed for {func.__name__}")
                        raise
                except Exception as e:
                    # Don't retry on non-specified exceptions
                    raise
            
            # This should never be reached, but just in case
            if last_exception:
                raise last_exception
                
        return wrapper
    return decorator