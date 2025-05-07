import os
import time
import json
import secrets
import requests
from functools import lru_cache
from typing import Optional, Dict, Any, List

class WebClientNonceRetriever:
    """
    Advanced Web Client Nonce Retrieval System
    
    Features:
    - Secure nonce generation and retrieval
    - Exponential backoff for network requests
    - Intelligent caching mechanism
    - Comprehensive error handling
    - Performance monitoring
    """
    
    def __init__(
        self, 
        nonce_endpoint: str = os.getenv('NONCE_ENDPOINT', 'https://default-nonce-service.com/nonce'),
        max_retries: int = 3,
        initial_timeout: float = 1.0,
        cache_size: int = 128,
        performance_threshold: float = 0.2
    ):
        """
        Initialize the WebClientNonceRetriever.
        
        Args:
            nonce_endpoint (str): URL for nonce retrieval
            max_retries (int): Maximum number of retry attempts
            initial_timeout (float): Initial timeout for exponential backoff
            cache_size (int): LRU cache size for nonce storage
            performance_threshold (float): Maximum acceptable retrieval time
        """
        self.nonce_endpoint = nonce_endpoint
        self.max_retries = max_retries
        self.initial_timeout = initial_timeout
        self.performance_threshold = performance_threshold
        self._nonce_cache: Dict[str, float] = {}
        self._performance_log: List[float] = []
    
    @lru_cache(maxsize=128)
    def _cached_nonce_retrieval(self, timestamp: float) -> Optional[str]:
        """
        Cached nonce retrieval with timestamp to enable cache invalidation.
        
        Args:
            timestamp (float): Current timestamp for cache key
        
        Returns:
            Optional[str]: Retrieved nonce or None
        """
        return self._retrieve_nonce_from_server()
    
    def _log_performance(self, retrieval_time: float) -> None:
        """
        Log and track performance metrics.
        
        Args:
            retrieval_time (float): Time taken for nonce retrieval
        """
        self._performance_log.append(retrieval_time)
        
        if retrieval_time > self.performance_threshold:
            print(f"PERFORMANCE WARNING: Nonce retrieval took {retrieval_time:.4f} seconds")
    
    def _retrieve_nonce_from_server(self) -> Optional[str]:
        """
        Retrieve nonce from server with exponential backoff and error handling.
        
        Returns:
            Optional[str]: Retrieved nonce or None
        
        Raises:
            Various network and parsing exceptions
        """
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                response = requests.get(
                    self.nonce_endpoint, 
                    timeout=(3, 10),  # Connection, read timeout
                    headers={'Accept': 'application/json'}
                )
                
                # Raise exception for bad HTTP status
                response.raise_for_status()
                
                # Validate JSON response
                nonce_data = response.json()
                nonce = self._extract_nonce(nonce_data)
                
                retrieval_time = time.time() - start_time
                self._log_performance(retrieval_time)
                
                return nonce
            
            except requests.RequestException as e:
                wait_time = self.initial_timeout * (2 ** attempt)
                print(f"Nonce retrieval attempt {attempt + 1} failed: {e}")
                time.sleep(wait_time)
            
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                print(f"Invalid nonce response: {e}")
                return None
        
        return None
    
    def _extract_nonce(self, nonce_data: Dict[str, Any]) -> Optional[str]:
        """
        Extract nonce from server response.
        
        Args:
            nonce_data (Dict[str, Any]): Server response data
        
        Returns:
            Optional[str]: Extracted nonce
        
        Raises:
            ValueError if nonce cannot be extracted
        """
        if not nonce_data or 'nonce' not in nonce_data:
            raise ValueError("No nonce found in response")
        
        nonce = nonce_data['nonce']
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("Invalid nonce format")
        
        return nonce
    
    def get_nonce(self) -> Optional[str]:
        """
        Get a nonce with intelligent caching and retrieval strategy.
        
        Returns:
            Optional[str]: A valid nonce or None
        """
        current_time = time.time()
        cached_nonce = self._cached_nonce_retrieval(current_time)
        
        if cached_nonce:
            self._nonce_cache[cached_nonce] = current_time
            return cached_nonce
        
        return None
    
    def validate_nonce(self, nonce: str, max_age: float = 300.0) -> bool:
        """
        Validate a previously retrieved nonce.
        
        Args:
            nonce (str): Nonce to validate
            max_age (float): Maximum allowed age for nonce
        
        Returns:
            bool: Whether nonce is valid
        """
        if not nonce or nonce not in self._nonce_cache:
            return False
        
        current_time = time.time()
        nonce_timestamp = self._nonce_cache.get(nonce, 0)
        
        return (current_time - nonce_timestamp) <= max_age
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """
        Retrieve performance metrics for nonce retrievals.
        
        Returns:
            Dict[str, float]: Performance metrics
        """
        if not self._performance_log:
            return {
                'average_retrieval_time': 0.0,
                'max_retrieval_time': 0.0,
                'min_retrieval_time': 0.0,
                'percentile_95': 0.0
            }
        
        sorted_times = sorted(self._performance_log)
        return {
            'average_retrieval_time': sum(sorted_times) / len(sorted_times),
            'max_retrieval_time': max(sorted_times),
            'min_retrieval_time': min(sorted_times),
            'percentile_95': sorted_times[int(len(sorted_times) * 0.95)]
        }