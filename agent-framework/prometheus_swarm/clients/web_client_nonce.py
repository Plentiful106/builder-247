import os
import secrets
import time

class WebClientNonceManager:
    """
    Manages nonce generation and validation for web clients.
    
    A nonce (number used once) is a unique, random value used to prevent replay attacks 
    and ensure request uniqueness. This implementation provides methods for generating 
    and validating nonces with configurable expiration.
    """
    
    def __init__(self, nonce_expiration_seconds=300):
        """
        Initialize the WebClientNonceManager.
        
        Args:
            nonce_expiration_seconds (int): Duration in seconds for which a nonce is valid.
                Defaults to 5 minutes (300 seconds).
        """
        self._nonce_store = {}
        self._nonce_expiration = nonce_expiration_seconds
    
    def generate_nonce(self):
        """
        Generate a unique, cryptographically secure nonce.
        
        Returns:
            str: A unique nonce token.
        """
        while True:
            nonce = secrets.token_urlsafe(32)
            if nonce not in self._nonce_store:
                current_time = time.time()
                self._nonce_store[nonce] = current_time
                self._clean_expired_nonces()
                return nonce
    
    def validate_nonce(self, nonce):
        """
        Validate a nonce and mark it as used.
        
        Args:
            nonce (str): The nonce to validate.
        
        Returns:
            bool: True if the nonce is valid and not expired, False otherwise.
        """
        if not nonce:
            return False
        
        current_time = time.time()
        self._clean_expired_nonces()
        
        if nonce in self._nonce_store:
            nonce_time = self._nonce_store[nonce]
            if current_time - nonce_time <= self._nonce_expiration:
                del self._nonce_store[nonce]  # Consume the nonce
                return True
        
        return False
    
    def _clean_expired_nonces(self):
        """
        Remove expired nonces from the nonce store.
        """
        current_time = time.time()
        expired_nonces = [
            nonce for nonce, timestamp in self._nonce_store.items()
            if current_time - timestamp > self._nonce_expiration
        ]
        
        for expired_nonce in expired_nonces:
            del self._nonce_store[expired_nonce]