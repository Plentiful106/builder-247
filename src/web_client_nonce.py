import os
import time
import secrets
import requests
from functools import lru_cache
from typing import Optional, Dict, Any

class WebClientNonceRetriever:
    """
    Manages web client nonce retrieval with advanced caching, retry, and error handling.
    
    Features:
    - Server endpoint nonce retrieval
    - Exponential backoff for network requests
    - Intelligent caching mechanism
    - Comprehensive error handling
    """
    
    def __init__(
        self, 
        nonce_endpoint: str = os.getenv('NONCE_ENDPOINT', 'https://default-nonce-service.com/nonce'),
        max_retries: int = 3,
        initial_timeout: float = 1.0,
        cache_size: int = 128
    ):
        """
        Initialize the WebClientNonceRetriever.
        
        Args:
            nonce_endpoint (str): URL for nonce retrieval
            max_retries (int): Maximum number of retry attempts
            initial_timeout (float): Initial timeout for exponential backoff
            cache_size (int): LRU cache size for nonce storage
        """
        self.nonce_endpoint = nonce_endpoint
        self.max_retries = max_retries
        self.initial_timeout = initial_timeout
        self._nonce_cache = {}  # Local nonce cache
    
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
    
    def _retrieve_nonce_from_server(self) -> Optional[str]:
        """
        Retrieve nonce from server with exponential backoff and error handling.
        
        Returns:
            Optional[str]: Retrieved nonce or None
        """
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                response = requests.get(
                    self.nonce_endpoint, 
                    timeout=(3, 10)  # Connection, read timeout
                )
                response.raise_for_status()
                
                nonce = response.json().get('nonce')
                retrieval_time = time.time() - start_time
                
                # Performance logging
                if retrieval_time > 0.2:
                    print(f"WARN: Nonce retrieval took {retrieval_time:.4f} seconds")
                
                return nonce
            
            except (requests.RequestException, ValueError) as e:
                wait_time = self.initial_timeout * (2 ** attempt)
                print(f"Nonce retrieval attempt {attempt + 1} failed: {e}")
                time.sleep(wait_time)
        
        return None
    
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