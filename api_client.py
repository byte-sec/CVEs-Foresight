# api_client.py
import requests
import time
import json
import hashlib
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from urllib.parse import urljoin, urlencode

from error_handling import (
    NetworkError, APIError, handle_exception, ErrorCategory, ErrorSeverity,
    retry_on_failure, error_tracker
)
from memory_manager import create_managed_cache
from validation import validate_nvd_search_params

logger = logging.getLogger(__name__)

class APIStatus(Enum):
    """API health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded" 
    DOWN = "down"
    RATE_LIMITED = "rate_limited"

@dataclass
class APIResponse:
    """Standardized API response wrapper"""
    success: bool
    data: Any
    status_code: int
    headers: Dict[str, str]
    response_time: float
    cached: bool = False
    error_message: Optional[str] = None

@dataclass
class RateLimitInfo:
    """Rate limiting information"""
    requests_per_second: float
    requests_per_minute: int
    requests_per_hour: int
    current_window_requests: int
    reset_time: datetime
    retry_after: Optional[int] = None

class APIClient:
    """
    Enhanced API client with caching, rate limiting, and error handling
    """
    
    def __init__(self, name: str, base_url: str, api_key: Optional[str] = None,
                 rate_limit_per_second: float = 5.0, timeout: int = 30):
        self.name = name
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.status = APIStatus.HEALTHY
        
        # Rate limiting
        self.rate_limit_per_second = rate_limit_per_second
        self.request_times: List[datetime] = []
        self.last_request_time: Optional[datetime] = None
        
        # Caching
        cache_name = f"{name.lower()}_api_cache"
        self.cache = create_managed_cache(cache_name, max_size=1000, ttl_seconds=3600)
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'cache_hits': 0,
            'rate_limit_hits': 0,
            'average_response_time': 0.0,
            'last_request_time': None
        }
        
        # Headers
        self.default_headers = {
            'User-Agent': f'CVE-Dashboard/{name}-Client',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        if self.api_key:
            if name.upper() == 'NVD':
                self.default_headers['apiKey'] = self.api_key
            elif name.upper() == 'GEMINI':
                self.default_headers['Authorization'] = f'Bearer {self.api_key}'
        
        logger.info(f"Initialized {name} API client with base URL: {base_url}")
    
    def _generate_cache_key(self, endpoint: str, params: Dict[str, Any]) -> str:
        """Generate cache key for request"""
        cache_data = {
            'endpoint': endpoint,
            'params': sorted(params.items()) if params else []
        }
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    def _should_cache(self, method: str, endpoint: str) -> bool:
        """Determine if request should be cached"""
        # Only cache GET requests for specific endpoints
        if method.upper() != 'GET':
            return False
        
        # Cache data retrieval endpoints but not status/health checks
        cacheable_patterns = ['/cves/', '/vulnerabilities/', '/search']
        return any(pattern in endpoint for pattern in cacheable_patterns)
    
    def _enforce_rate_limit(self) -> None:
        """Enforce rate limiting with exponential backoff"""
        now = datetime.now()
        
        # Clean old request times (keep only last minute)
        cutoff_time = now - timedelta(minutes=1)
        self.request_times = [t for t in self.request_times if t > cutoff_time]
        
        # Check rate limit
        requests_last_second = sum(
            1 for t in self.request_times 
            if t > now - timedelta(seconds=1)
        )
        
        if requests_last_second >= self.rate_limit_per_second:
            delay = 1.0 / self.rate_limit_per_second
            
            # Add jitter to prevent thundering herd
            import random
            jitter = random.uniform(0.1, 0.3)
            total_delay = delay + jitter
            
            logger.debug(f"Rate limiting: waiting {total_delay:.2f}s")
            time.sleep(total_delay)
            self.stats['rate_limit_hits'] += 1
        
        self.request_times.append(now)
        self.last_request_time = now
    
    @retry_on_failure(max_retries=3, delay=1.0, backoff_factor=2.0)
    @handle_exception(category=ErrorCategory.API, reraise=True)
    def request(self, method: str, endpoint: str, params: Optional[Dict[str, Any]] = None,
                data: Optional[Dict[str, Any]] = None, use_cache: bool = True,
                cache_ttl: Optional[int] = None) -> APIResponse:
        """
        Make API request with caching, rate limiting, and error handling
        """
        start_time = time.time()
        
        # Validate parameters for NVD requests
        if self.name.upper() == 'NVD' and params:
            params = validate_nvd_search_params(params)
        
        # Check cache first
        cache_key = None
        if use_cache and self._should_cache(method, endpoint):
            cache_key = self._generate_cache_key(endpoint, params or {})
            cached_response = self.cache.get(cache_key)
            if cached_response:
                logger.debug(f"Cache hit for {endpoint}")
                self.stats['cache_hits'] += 1
                cached_response.cached = True
                return cached_response
        
        # Enforce rate limiting
        self._enforce_rate_limit()
        
        # Build URL
        url = urljoin(self.base_url, endpoint.lstrip('/'))
        
        # Prepare request
        headers = self.default_headers.copy()
        request_kwargs = {
            'method': method.upper(),
            'url': url,
            'headers': headers,
            'timeout': self.timeout
        }
        
        if params:
            if method.upper() == 'GET':
                request_kwargs['params'] = params
            else:
                request_kwargs['json'] = params
        
        if data:
            request_kwargs['json'] = data
        
        # Log request
        logger.debug(f"API Request: {method.upper()} {url}")
        if params and logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Parameters: {params}")
        
        try:
            # Make request
            response = requests.request(**request_kwargs)
            response_time = time.time() - start_time
            
            # Update statistics
            self.stats['total_requests'] += 1
            self.stats['last_request_time'] = datetime.now().isoformat()
            
            # Update average response time
            current_avg = self.stats['average_response_time']
            total_requests = self.stats['total_requests']
            self.stats['average_response_time'] = (
                (current_avg * (total_requests - 1) + response_time) / total_requests
            )
            
            # Handle response
            if response.status_code == 200:
                self.stats['successful_requests'] += 1
                self.status = APIStatus.HEALTHY
                
                try:
                    response_data = response.json()
                except ValueError:
                    response_data = response.text
                
                api_response = APIResponse(
                    success=True,
                    data=response_data,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    response_time=response_time
                )
                
                # Cache successful responses
                if cache_key and self._should_cache(method, endpoint):
                    if cache_ttl:
                        # Create temporary cache with custom TTL
                        temp_cache = create_managed_cache(
                            f"{cache_key}_temp", max_size=1, ttl_seconds=cache_ttl
                        )
                        temp_cache.set(cache_key, api_response)
                    else:
                        self.cache.set(cache_key, api_response)
                
                logger.debug(f"API Response: {response.status_code} in {response_time:.2f}s")
                return api_response
            
            elif response.status_code == 429:  # Rate limited
                self.stats['failed_requests'] += 1
                self.status = APIStatus.RATE_LIMITED
                
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    delay = int(retry_after)
                    logger.warning(f"Rate limited, waiting {delay}s")
                    time.sleep(delay)
                
                raise NetworkError(
                    f"Rate limited by {self.name} API",
                    status_code=response.status_code,
                    url=url,
                    severity=ErrorSeverity.HIGH
                )
            
            else:  # Other HTTP errors
                self.stats['failed_requests'] += 1
                
                if response.status_code >= 500:
                    self.status = APIStatus.DOWN
                else:
                    self.status = APIStatus.DEGRADED
                
                error_message = f"{self.name} API error: {response.status_code}"
                try:
                    error_data = response.json()
                    if 'message' in error_data:
                        error_message += f" - {error_data['message']}"
                except:
                    pass
                
                raise APIError(
                    error_message,
                    api_name=self.name,
                    endpoint=endpoint,
                    response_data=response.text[:500],
                    severity=ErrorSeverity.HIGH if response.status_code >= 500 else ErrorSeverity.MEDIUM
                )
        
        except requests.exceptions.Timeout:
            self.stats['failed_requests'] += 1
            self.status = APIStatus.DEGRADED
            raise NetworkError(
                f"Timeout connecting to {self.name} API",
                url=url,
                severity=ErrorSeverity.HIGH
            )
        
        except requests.exceptions.ConnectionError:
            self.stats['failed_requests'] += 1
            self.status = APIStatus.DOWN
            raise NetworkError(
                f"Connection error to {self.name} API",
                url=url,
                severity=ErrorSeverity.CRITICAL
            )
        
        except requests.exceptions.RequestException as e:
            self.stats['failed_requests'] += 1
            self.status = APIStatus.DEGRADED
            raise NetworkError(
                f"Request error to {self.name} API: {str(e)}",
                url=url,
                severity=ErrorSeverity.MEDIUM
            )
    
    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None, **kwargs) -> APIResponse:
        """GET request"""
        return self.request('GET', endpoint, params=params, **kwargs)
    
    def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> APIResponse:
        """POST request"""
        return self.request('POST', endpoint, data=data, **kwargs)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get API client statistics"""
        stats = self.stats.copy()
        stats.update({
            'status': self.status.value,
            'cache_size': self.cache.size() if self.cache else 0,
            'cache_stats': self.cache.get_stats() if self.cache else {},
            'rate_limit_per_second': self.rate_limit_per_second,
            'recent_request_count': len(self.request_times)
        })
        return stats
    
    def clear_cache(self) -> None:
        """Clear API cache"""
        if self.cache:
            self.cache.clear()
            logger.info(f"Cleared {self.name} API cache")
    
    def health_check(self) -> bool:
        """Perform API health check"""
        try:
            # Use a lightweight endpoint for health check
            if self.name.upper() == 'NVD':
                response = self.get('/cves/2.0', params={'resultsPerPage': 1}, use_cache=False)
            else:
                # Generic health check
                response = self.get('/', use_cache=False)
            
            is_healthy = response.success and response.status_code == 200
            self.status = APIStatus.HEALTHY if is_healthy else APIStatus.DEGRADED
            
            logger.info(f"{self.name} API health check: {'PASS' if is_healthy else 'FAIL'}")
            return is_healthy
            
        except Exception as e:
            logger.error(f"{self.name} API health check failed: {e}")
            self.status = APIStatus.DOWN
            return False

class APIManager:
    """
    Manages multiple API clients
    """
    
    def __init__(self):
        self.clients: Dict[str, APIClient] = {}
        self._health_check_interval = 300  # 5 minutes
        self._last_health_check = {}
    
    def register_client(self, client: APIClient) -> None:
        """Register an API client"""
        self.clients[client.name.lower()] = client
        logger.info(f"Registered API client: {client.name}")
    
    def get_client(self, name: str) -> Optional[APIClient]:
        """Get API client by name"""
        return self.clients.get(name.lower())
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all API clients"""
        return {name: client.get_stats() for name, client in self.clients.items()}
    
    def health_check_all(self, force: bool = False) -> Dict[str, bool]:
        """Perform health check on all clients"""
        now = datetime.now()
        results = {}
        
        for name, client in self.clients.items():
            last_check = self._last_health_check.get(name)
            
            if (force or not last_check or 
                (now - last_check).total_seconds() > self._health_check_interval):
                
                results[name] = client.health_check()
                self._last_health_check[name] = now
            else:
                # Use cached status
                results[name] = client.status == APIStatus.HEALTHY
        
        return results
    
    def clear_all_caches(self) -> None:
        """Clear caches for all API clients"""
        for client in self.clients.values():
            client.clear_cache()
        logger.info("Cleared all API client caches")

# Global API manager instance
api_manager = APIManager()

def create_nvd_client(api_key: str) -> APIClient:
    """Create and register NVD API client"""
    client = APIClient(
        name="NVD",
        base_url="https://services.nvd.nist.gov/rest/json",
        api_key=api_key,
        rate_limit_per_second=5.0,  # NVD allows 5 requests per second with API key
        timeout=30
    )
    api_manager.register_client(client)
    return client

def create_gemini_client(api_key: str) -> APIClient:
    """Create and register Gemini API client"""
    client = APIClient(
        name="Gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        api_key=api_key,
        rate_limit_per_second=10.0,  # Gemini has more generous limits
        timeout=45
    )
    api_manager.register_client(client)
    return client

def get_api_client(name: str) -> Optional[APIClient]:
    """Get API client by name"""
    return api_manager.get_client(name)

def get_all_api_stats() -> Dict[str, Dict[str, Any]]:
    """Get statistics for all API clients"""
    return api_manager.get_all_stats()

def health_check_apis() -> Dict[str, bool]:
    """Perform health check on all APIs"""
    return api_manager.health_check_all()