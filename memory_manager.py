# memory_manager.py
import gc
import sys
import threading
import time
import weakref
import psutil
import logging
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
from collections import OrderedDict
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class MemoryStats:
    """Memory usage statistics"""
    total_memory_mb: float
    used_memory_mb: float
    available_memory_mb: float
    memory_percent: float
    cache_size_mb: float
    timestamp: datetime

class LRUCache:
    """
    Least Recently Used cache with size limits and TTL support
    """
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache = OrderedDict()
        self._access_times = {}
        self._lock = threading.RLock()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get item from cache"""
        with self._lock:
            if key not in self._cache:
                return default
            
            # Check TTL
            if self._is_expired(key):
                self._remove_key(key)
                return default
            
            # Move to end (most recently used)
            value = self._cache[key]
            self._cache.move_to_end(key)
            self._access_times[key] = datetime.now()
            return value
    
    def set(self, key: str, value: Any) -> None:
        """Set item in cache"""
        with self._lock:
            # Remove if exists
            if key in self._cache:
                del self._cache[key]
            
            # Add new item
            self._cache[key] = value
            self._access_times[key] = datetime.now()
            
            # Enforce size limit
            while len(self._cache) > self.max_size:
                oldest_key = next(iter(self._cache))
                self._remove_key(oldest_key)
    
    def remove(self, key: str) -> bool:
        """Remove specific key from cache"""
        with self._lock:
            if key in self._cache:
                self._remove_key(key)
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()
    
    def size(self) -> int:
        """Get current cache size"""
        return len(self._cache)
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed"""
        with self._lock:
            expired_keys = [key for key in self._cache if self._is_expired(key)]
            for key in expired_keys:
                self._remove_key(key)
            return len(expired_keys)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_size = sum(sys.getsizeof(v) for v in self._cache.values())
            return {
                'entries': len(self._cache),
                'max_size': self.max_size,
                'size_bytes': total_size,
                'size_mb': total_size / (1024 * 1024),
                'ttl_seconds': self.ttl_seconds
            }
    
    def _is_expired(self, key: str) -> bool:
        """Check if cache entry is expired"""
        if key not in self._access_times:
            return True
        
        age = datetime.now() - self._access_times[key]
        return age.total_seconds() > self.ttl_seconds
    
    def _remove_key(self, key: str) -> None:
        """Remove key from both cache and access times"""
        if key in self._cache:
            del self._cache[key]
        if key in self._access_times:
            del self._access_times[key]

class MemoryManager:
    """
    Central memory management system
    """
    def __init__(self):
        self._caches: Dict[str, LRUCache] = {}
        self._weak_refs: List[weakref.ref] = []
        self._monitoring_active = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stats_history: List[MemoryStats] = []
        self._cleanup_callbacks: List[Callable] = []
        self._lock = threading.RLock()
        
        # Memory thresholds (as percentages)
        self.warning_threshold = 80.0
        self.critical_threshold = 90.0
        self.cleanup_threshold = 85.0
    
    def create_cache(self, name: str, max_size: int = 1000, ttl_seconds: int = 3600) -> LRUCache:
        """Create a new managed cache"""
        with self._lock:
            cache = LRUCache(max_size, ttl_seconds)
            self._caches[name] = cache
            logger.info(f"Created cache '{name}' with max_size={max_size}, ttl={ttl_seconds}s")
            return cache
    
    def get_cache(self, name: str) -> Optional[LRUCache]:
        """Get existing cache by name"""
        return self._caches.get(name)
    
    def register_cleanup_callback(self, callback: Callable) -> None:
        """Register a callback for memory cleanup events"""
        self._cleanup_callbacks.append(callback)
    
    def add_weak_reference(self, obj: Any) -> None:
        """Add a weak reference for memory tracking"""
        self._weak_refs.append(weakref.ref(obj))
    
    def start_monitoring(self, interval_seconds: int = 30) -> None:
        """Start memory monitoring thread"""
        if self._monitoring_active:
            return
        
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self._monitor_thread.start()
        logger.info(f"Memory monitoring started with {interval_seconds}s interval")
    
    def stop_monitoring(self) -> None:
        """Stop memory monitoring"""
        self._monitoring_active = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        logger.info("Memory monitoring stopped")
    
    def get_memory_stats(self) -> MemoryStats:
        """Get current memory statistics"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()
            
            # Calculate cache sizes
            cache_size_bytes = sum(
                sum(sys.getsizeof(item) for item in cache._cache.values())
                for cache in self._caches.values()
            )
            
            return MemoryStats(
                total_memory_mb=system_memory.total / (1024 * 1024),
                used_memory_mb=memory_info.rss / (1024 * 1024),
                available_memory_mb=system_memory.available / (1024 * 1024),
                memory_percent=system_memory.percent,
                cache_size_mb=cache_size_bytes / (1024 * 1024),
                timestamp=datetime.now()
            )
        except Exception as e:
            logger.error(f"Failed to get memory stats: {e}")
            return MemoryStats(0, 0, 0, 0, 0, datetime.now())
    
    def force_cleanup(self) -> Dict[str, int]:
        """Force memory cleanup and return cleanup statistics"""
        logger.info("Starting forced memory cleanup")
        
        cleanup_stats = {
            'cache_entries_removed': 0,
            'dead_references_removed': 0,
            'garbage_collected': 0
        }
        
        # Clean up caches
        with self._lock:
            for name, cache in self._caches.items():
                initial_size = cache.size()
                expired_removed = cache.cleanup_expired()
                
                # If still over threshold, remove oldest entries
                if cache.size() > cache.max_size * 0.5:
                    target_size = int(cache.max_size * 0.3)
                    while cache.size() > target_size:
                        oldest_key = next(iter(cache._cache))
                        cache._remove_key(oldest_key)
                
                removed = initial_size - cache.size()
                cleanup_stats['cache_entries_removed'] += removed
                logger.debug(f"Cache '{name}': removed {removed} entries")
        
        # Clean up dead weak references
        initial_refs = len(self._weak_refs)
        self._weak_refs = [ref for ref in self._weak_refs if ref() is not None]
        cleanup_stats['dead_references_removed'] = initial_refs - len(self._weak_refs)
        
        # Run garbage collection
        cleanup_stats['garbage_collected'] = gc.collect()
        
        # Call cleanup callbacks
        for callback in self._cleanup_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error(f"Cleanup callback failed: {e}")
        
        logger.info(f"Memory cleanup completed: {cleanup_stats}")
        return cleanup_stats
    
    def get_cache_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all caches"""
        return {name: cache.get_stats() for name, cache in self._caches.items()}
    
    def get_memory_history(self, hours: int = 24) -> List[MemoryStats]:
        """Get memory statistics history"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [stat for stat in self._stats_history if stat.timestamp >= cutoff_time]
    
    def _monitoring_loop(self, interval_seconds: int) -> None:
        """Main monitoring loop"""
        while self._monitoring_active:
            try:
                stats = self.get_memory_stats()
                
                # Store in history
                self._stats_history.append(stats)
                
                # Keep only last 24 hours of history
                cutoff_time = datetime.now() - timedelta(hours=24)
                self._stats_history = [
                    s for s in self._stats_history if s.timestamp >= cutoff_time
                ]
                
                # Check thresholds
                if stats.memory_percent >= self.critical_threshold:
                    logger.critical(f"Critical memory usage: {stats.memory_percent:.1f}%")
                    self.force_cleanup()
                elif stats.memory_percent >= self.cleanup_threshold:
                    logger.warning(f"High memory usage: {stats.memory_percent:.1f}%, running cleanup")
                    self._cleanup_expired_caches()
                elif stats.memory_percent >= self.warning_threshold:
                    logger.warning(f"Memory usage warning: {stats.memory_percent:.1f}%")
                
                time.sleep(interval_seconds)
                
            except Exception as e:
                logger.error(f"Memory monitoring error: {e}")
                time.sleep(interval_seconds)
    
    def _cleanup_expired_caches(self) -> None:
        """Clean up expired cache entries"""
        total_removed = 0
        for name, cache in self._caches.items():
            removed = cache.cleanup_expired()
            total_removed += removed
            if removed > 0:
                logger.debug(f"Cache '{name}': removed {removed} expired entries")
        
        if total_removed > 0:
            logger.info(f"Cleaned up {total_removed} expired cache entries")

# Global memory manager instance
memory_manager = MemoryManager()

def create_managed_cache(name: str, max_size: int = 1000, ttl_seconds: int = 3600) -> LRUCache:
    """Create a new managed cache"""
    return memory_manager.create_cache(name, max_size, ttl_seconds)

def get_cache(name: str) -> Optional[LRUCache]:
    """Get managed cache by name"""
    return memory_manager.get_cache(name)

def track_object(obj: Any) -> None:
    """Add object to memory tracking"""
    memory_manager.add_weak_reference(obj)

def start_memory_monitoring() -> None:
    """Start global memory monitoring"""
    memory_manager.start_monitoring()

def get_memory_usage() -> MemoryStats:
    """Get current memory usage statistics"""
    return memory_manager.get_memory_stats()

def cleanup_memory() -> Dict[str, int]:
    """Force memory cleanup"""
    return memory_manager.force_cleanup()

def register_cleanup_callback(callback: Callable) -> None:
    """Register callback for memory cleanup events"""
    memory_manager.register_cleanup_callback(callback)

class MemoryOptimizedDataFrame:
    """
    Memory-optimized data structure for CVE data
    """
    def __init__(self, max_size: int = 5000):
        self.max_size = max_size
        self._data: OrderedDict = OrderedDict()
        self._lock = threading.RLock()
    
    def add(self, key: str, data: Dict[str, Any]) -> None:
        """Add data with automatic size management"""
        with self._lock:
            # Remove if exists to update position
            if key in self._data:
                del self._data[key]
            
            self._data[key] = data
            
            # Enforce size limit
            while len(self._data) > self.max_size:
                oldest_key = next(iter(self._data))
                del self._data[oldest_key]
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get data and mark as recently accessed"""
        with self._lock:
            if key in self._data:
                # Move to end (most recently used)
                value = self._data[key]
                self._data.move_to_end(key)
                return value
            return None
    
    def get_all(self) -> List[Dict[str, Any]]:
        """Get all data as list"""
        with self._lock:
            return list(self._data.values())
    
    def clear(self) -> None:
        """Clear all data"""
        with self._lock:
            self._data.clear()
    
    def size(self) -> int:
        """Get current size"""
        return len(self._data)
    
    def get_memory_usage(self) -> float:
        """Get approximate memory usage in MB"""
        total_size = sum(sys.getsizeof(item) for item in self._data.values())
        return total_size / (1024 * 1024)