# config_manager.py
import json
import os
import base64
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from validation import validate_configuration, ValidationError

logger = logging.getLogger(__name__)

# Configuration file paths
BASE_DIR = Path(__file__).parent.absolute()
CONFIG_FILE = BASE_DIR / "config.json"
ENCRYPTED_CONFIG_FILE = BASE_DIR / "config.encrypted"
KEY_FILE = BASE_DIR / ".config_key"

# Default configuration values
DEFAULT_CONFIG = {
    "NVD_API_KEY": "",
    "GEMINI_API_KEY": "",
    "LOG_LEVEL": "INFO",
    "DATABASE_PATH": "cve_dashboard.db",
    "SYNC_BATCH_SIZE": 2000,
    "API_TIMEOUT": 30,
    "RATE_LIMIT_DELAY": 6,
    "MAX_SEARCH_RESULTS": 10000,
    "KEV_UPDATE_FREQUENCY": 24,  # hours
    "AUTO_SYNC_ENABLED": False,
    "ENABLE_AI_ANALYSIS": True,
    "GUI_THEME": "dark",
    "BACKUP_RETENTION_DAYS": 30,
    "LOG_RETENTION_DAYS": 7
}

class ConfigurationError(Exception):
    """Raised when configuration operations fail"""
    pass

class ConfigManager:
    def __init__(self):
        self._config_cache = None
        self._encryption_key = None
        self._use_encryption = self._should_use_encryption()
    
    def _should_use_encryption(self) -> bool:
        """Determine if encryption should be used based on environment"""
        # Use encryption if cryptography is available and not in development mode
        try:
            from cryptography.fernet import Fernet
            return not os.environ.get('CVE_DEV_MODE', '').lower() == 'true'
        except ImportError:
            logger.warning("Cryptography library not available, using plain text config")
            return False
    
    def _get_encryption_key(self) -> bytes:
        """Get or create encryption key"""
        if self._encryption_key:
            return self._encryption_key
        
        if KEY_FILE.exists():
            # Load existing key
            try:
                with open(KEY_FILE, 'rb') as f:
                    self._encryption_key = f.read()
                logger.debug("Loaded existing encryption key")
            except Exception as e:
                logger.error(f"Failed to load encryption key: {e}")
                raise ConfigurationError("Failed to load encryption key")
        else:
            # Generate new key
            self._encryption_key = Fernet.generate_key()
            try:
                # Save key with restricted permissions
                with open(KEY_FILE, 'wb') as f:
                    f.write(self._encryption_key)
                os.chmod(KEY_FILE, 0o600)  # Read/write for owner only
                logger.info("Generated new encryption key")
            except Exception as e:
                logger.error(f"Failed to save encryption key: {e}")
                raise ConfigurationError("Failed to save encryption key")
        
        return self._encryption_key
    
    def _encrypt_data(self, data: str) -> bytes:
        """Encrypt configuration data"""
        if not self._use_encryption:
            return data.encode('utf-8')
        
        key = self._get_encryption_key()
        fernet = Fernet(key)
        return fernet.encrypt(data.encode('utf-8'))
    
    def _decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt configuration data"""
        if not self._use_encryption:
            return encrypted_data.decode('utf-8')
        
        key = self._get_encryption_key()
        fernet = Fernet(key)
        try:
            return fernet.decrypt(encrypted_data).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to decrypt configuration: {e}")
            raise ConfigurationError("Failed to decrypt configuration")
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables, files, or defaults"""
        if self._config_cache is not None:
            return self._config_cache.copy()
        
        config = DEFAULT_CONFIG.copy()
        
        # 1. Load from environment variables first (highest priority)
        env_config = self._load_from_environment()
        if env_config:
            config.update(env_config)
            logger.info("Loaded configuration from environment variables")
        
        # 2. Load from encrypted file
        elif self._use_encryption and ENCRYPTED_CONFIG_FILE.exists():
            file_config = self._load_encrypted_config()
            if file_config:
                config.update(file_config)
                logger.info("Loaded encrypted configuration file")
        
        # 3. Load from plain text file (legacy support)
        elif CONFIG_FILE.exists():
            file_config = self._load_plain_config()
            if file_config:
                config.update(file_config)
                logger.info("Loaded plain text configuration file")
                
                # Migrate to encrypted format if possible
                if self._use_encryption:
                    logger.info("Migrating configuration to encrypted format")
                    self.save_config(file_config)
        
        # 4. Use defaults
        else:
            logger.info("Using default configuration")
        
        # Validate configuration
        try:
            config = validate_configuration(config)
        except ValidationError as e:
            logger.error(f"Configuration validation failed: {e}")
            # Use defaults for invalid config
            config = DEFAULT_CONFIG.copy()
        
        # Cache the configuration
        self._config_cache = config.copy()
        
        # Log configuration status (without sensitive data)
        self._log_config_status(config)
        
        return config.copy()
    
    def _load_from_environment(self) -> Optional[Dict[str, Any]]:
        """Load configuration from environment variables"""
        env_config = {}
        
        for key in DEFAULT_CONFIG.keys():
            env_value = os.environ.get(f"CVE_{key}")
            if env_value:
                # Convert string values to appropriate types
                if key in ['SYNC_BATCH_SIZE', 'API_TIMEOUT', 'RATE_LIMIT_DELAY', 
                          'MAX_SEARCH_RESULTS', 'KEV_UPDATE_FREQUENCY', 
                          'BACKUP_RETENTION_DAYS', 'LOG_RETENTION_DAYS']:
                    try:
                        env_config[key] = int(env_value)
                    except ValueError:
                        logger.warning(f"Invalid integer value for {key}: {env_value}")
                        continue
                elif key in ['AUTO_SYNC_ENABLED', 'ENABLE_AI_ANALYSIS']:
                    env_config[key] = env_value.lower() in ('true', '1', 'yes', 'on')
                else:
                    env_config[key] = env_value
        
        return env_config if env_config else None
    
    def _load_encrypted_config(self) -> Optional[Dict[str, Any]]:
        """Load configuration from encrypted file"""
        try:
            with open(ENCRYPTED_CONFIG_FILE, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_json = self._decrypt_data(encrypted_data)
            return json.loads(decrypted_json)
            
        except Exception as e:
            logger.error(f"Failed to load encrypted configuration: {e}")
            return None
    
    def _load_plain_config(self) -> Optional[Dict[str, Any]]:
        """Load configuration from plain text file"""
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration file: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to load configuration file: {e}")
            return None
    
    def save_config(self, config_data: Dict[str, Any]) -> bool:
        """Save configuration to appropriate format"""
        try:
            # Validate before saving
            validated_config = validate_configuration(config_data)
            
            # Merge with existing configuration
            current_config = self.load_config()
            current_config.update(validated_config)
            
            if self._use_encryption:
                self._save_encrypted_config(current_config)
            else:
                self._save_plain_config(current_config)
            
            # Update cache
            self._config_cache = current_config.copy()
            
            logger.info("Configuration saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def _save_encrypted_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to encrypted file"""
        config_json = json.dumps(config, indent=2)
        encrypted_data = self._encrypt_data(config_json)
        
        # Write to temporary file first, then rename (atomic operation)
        temp_file = ENCRYPTED_CONFIG_FILE.with_suffix('.tmp')
        try:
            with open(temp_file, 'wb') as f:
                f.write(encrypted_data)
            os.chmod(temp_file, 0o600)  # Restrict permissions
            temp_file.replace(ENCRYPTED_CONFIG_FILE)
            
            # Remove old plain text file if it exists
            if CONFIG_FILE.exists():
                CONFIG_FILE.unlink()
                logger.info("Removed old plain text configuration file")
                
        except Exception as e:
            if temp_file.exists():
                temp_file.unlink()
            raise e
    
    def _save_plain_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to plain text file"""
        # Write to temporary file first, then rename (atomic operation)
        temp_file = CONFIG_FILE.with_suffix('.tmp')
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            temp_file.replace(CONFIG_FILE)
        except Exception as e:
            if temp_file.exists():
                temp_file.unlink()
            raise e
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        config = self.load_config()
        return config.get(key, default)
    
    def set(self, key: str, value: Any) -> bool:
        """Set a configuration value"""
        return self.save_config({key: value})
    
    def has_required_keys(self) -> bool:
        """Check if required configuration keys are present"""
        config = self.load_config()
        return bool(config.get('NVD_API_KEY'))
    
    def get_api_keys(self) -> Dict[str, str]:
        """Get API keys (for backward compatibility)"""
        config = self.load_config()
        return {
            'NVD_API_KEY': config.get('NVD_API_KEY', ''),
            'GEMINI_API_KEY': config.get('GEMINI_API_KEY', '')
        }
    
    def _log_config_status(self, config: Dict[str, Any]) -> None:
        """Log configuration status without sensitive information"""
        status = {
            'nvd_key_configured': bool(config.get('NVD_API_KEY')),
            'gemini_key_configured': bool(config.get('GEMINI_API_KEY')),
            'log_level': config.get('LOG_LEVEL'),
            'encryption_enabled': self._use_encryption,
            'config_source': self._get_config_source()
        }
        logger.info(f"Configuration status: {status}")
    
    def _get_config_source(self) -> str:
        """Determine the source of configuration"""
        if any(os.environ.get(f"CVE_{key}") for key in DEFAULT_CONFIG.keys()):
            return "environment"
        elif self._use_encryption and ENCRYPTED_CONFIG_FILE.exists():
            return "encrypted_file"
        elif CONFIG_FILE.exists():
            return "plain_file"
        else:
            return "defaults"
    
    def clear_cache(self) -> None:
        """Clear the configuration cache"""
        self._config_cache = None
    
    def backup_config(self) -> bool:
        """Create a backup of current configuration"""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if self._use_encryption and ENCRYPTED_CONFIG_FILE.exists():
                backup_file = BASE_DIR / f"config_backup_{timestamp}.encrypted"
                ENCRYPTED_CONFIG_FILE.copy2(backup_file)
            elif CONFIG_FILE.exists():
                backup_file = BASE_DIR / f"config_backup_{timestamp}.json"
                CONFIG_FILE.copy2(backup_file)
            else:
                logger.warning("No configuration file to backup")
                return False
            
            logger.info(f"Configuration backed up to {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to backup configuration: {e}")
            return False

# Global configuration manager instance
_config_manager = ConfigManager()

# Public API functions (for backward compatibility)
def load_config() -> Dict[str, Any]:
    """Load configuration (backward compatible)"""
    return _config_manager.load_config()

def save_config(config_data: Dict[str, Any]) -> bool:
    """Save configuration (backward compatible)"""
    return _config_manager.save_config(config_data)

def get_config_value(key: str, default: Any = None) -> Any:
    """Get a single configuration value"""
    return _config_manager.get(key, default)

def set_config_value(key: str, value: Any) -> bool:
    """Set a single configuration value"""
    return _config_manager.set(key, value)

def has_required_config() -> bool:
    """Check if all required configuration is present"""
    return _config_manager.has_required_keys()

def reload_config() -> Dict[str, Any]:
    """Force reload configuration from disk"""
    _config_manager.clear_cache()
    return _config_manager.load_config()