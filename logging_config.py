# logging_config.py
import logging
import logging.handlers
import os
from datetime import datetime

def setup_logging(log_level=logging.INFO, log_to_file=True):
    """
    Set up comprehensive logging for the CVE Dashboard application.
    
    Args:
        log_level: Minimum logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_to_file: Whether to write logs to files in addition to console
    """
    
    # Create logs directory if it doesn't exist
    if log_to_file:
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)-15s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(simple_formatter)
    root_logger.addHandler(console_handler)
    
    if log_to_file:
        # Main application log file (rotating)
        app_log_file = os.path.join(log_dir, "cve_dashboard.log")
        app_handler = logging.handlers.RotatingFileHandler(
            app_log_file, 
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        app_handler.setLevel(log_level)
        app_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(app_handler)
        
        # Error-only log file
        error_log_file = os.path.join(log_dir, "errors.log")
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(error_handler)
        
        # Database operations log
        db_log_file = os.path.join(log_dir, "database.log")
        db_handler = logging.handlers.RotatingFileHandler(
            db_log_file,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3,
            encoding='utf-8'
        )
        db_handler.setLevel(logging.DEBUG)
        db_handler.setFormatter(detailed_formatter)
        
        # Add DB handler only to database logger
        db_logger = logging.getLogger('database')
        db_logger.addHandler(db_handler)
        db_logger.setLevel(logging.DEBUG)
    
    # Configure specific loggers with appropriate levels
    configure_module_loggers(log_level)
    
    # Log the startup
    logger = logging.getLogger(__name__)
    logger.info("="*60)
    logger.info("CVE Dashboard Application Starting")
    logger.info(f"Log level: {logging.getLevelName(log_level)}")
    logger.info(f"Log to file: {log_to_file}")
    logger.info("="*60)

def configure_module_loggers(base_level):
    """Configure logging levels for different modules"""
    
    # Database operations - more verbose in debug mode
    db_logger = logging.getLogger('database')
    db_logger.setLevel(logging.DEBUG if base_level <= logging.DEBUG else logging.INFO)
    
    # API operations
    api_logger = logging.getLogger('backend.api_handler')
    api_logger.setLevel(base_level)
    
    # NVD API calls
    nvd_logger = logging.getLogger('backend.nvd_searcher')
    nvd_logger.setLevel(base_level)
    
    # AI service
    ai_logger = logging.getLogger('backend.ai_service')
    ai_logger.setLevel(base_level)
    
    # Sync operations
    sync_logger = logging.getLogger('backend.sync_manager')
    sync_logger.setLevel(base_level)
    
    # Threat intelligence
    threat_logger = logging.getLogger('backend.threat_intel')
    threat_logger.setLevel(base_level)
    
    # GUI operations (usually less verbose)
    gui_logger = logging.getLogger('gui')
    gui_logger.setLevel(logging.WARNING if base_level < logging.WARNING else base_level)
    
    # Third-party libraries (keep quiet unless debugging)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)

def get_logger(name):
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Usually __name__ from the calling module
        
    Returns:
        Logger instance configured for the module
    """
    return logging.getLogger(name)

def log_function_call(logger, func_name, args=None, kwargs=None):
    """
    Helper function to log function calls with parameters.
    
    Args:
        logger: Logger instance
        func_name: Name of the function being called
        args: Positional arguments (optional)
        kwargs: Keyword arguments (optional)
    """
    if logger.isEnabledFor(logging.DEBUG):
        params = []
        if args:
            params.extend([str(arg)[:100] for arg in args])  # Truncate long args
        if kwargs:
            params.extend([f"{k}={str(v)[:100]}" for k, v in kwargs.items()])
        
        param_str = ", ".join(params)
        if len(param_str) > 200:
            param_str = param_str[:200] + "..."
            
        logger.debug(f"Calling {func_name}({param_str})")

def log_performance(logger, operation_name, start_time, end_time, details=None):
    """
    Log performance metrics for operations.
    
    Args:
        logger: Logger instance
        operation_name: Description of the operation
        start_time: Start timestamp
        end_time: End timestamp
        details: Additional details (e.g., number of records processed)
    """
    duration = end_time - start_time
    msg = f"Performance: {operation_name} took {duration:.2f}s"
    if details:
        msg += f" ({details})"
    
    if duration > 5.0:  # Log slow operations as warnings
        logger.warning(msg)
    else:
        logger.info(msg)

def log_api_call(logger, api_name, endpoint, status_code=None, response_time=None, error=None):
    """
    Log API calls with standardized format.
    
    Args:
        logger: Logger instance
        api_name: Name of the API (e.g., "NVD", "Gemini")
        endpoint: API endpoint or operation
        status_code: HTTP status code (if applicable)
        response_time: Response time in seconds
        error: Error message if call failed
    """
    if error:
        logger.error(f"API Call Failed: {api_name} {endpoint} - {error}")
    else:
        msg = f"API Call: {api_name} {endpoint}"
        if status_code:
            msg += f" [{status_code}]"
        if response_time:
            msg += f" ({response_time:.2f}s)"
        
        if status_code and status_code >= 400:
            logger.warning(msg)
        else:
            logger.info(msg)

def create_session_id():
    """Create a unique session ID for tracking related operations"""
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")

# Context manager for operation logging
class LoggedOperation:
    """Context manager for logging operations with timing"""
    
    def __init__(self, logger, operation_name, details=None):
        self.logger = logger
        self.operation_name = operation_name
        self.details = details
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        msg = f"Starting: {self.operation_name}"
        if self.details:
            msg += f" ({self.details})"
        self.logger.info(msg)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        if exc_type is None:
            msg = f"Completed: {self.operation_name} in {duration:.2f}s"
            if self.details:
                msg += f" ({self.details})"
            self.logger.info(msg)
        else:
            self.logger.error(f"Failed: {self.operation_name} after {duration:.2f}s - {exc_val}")
        
        return False  # Don't suppress exceptions