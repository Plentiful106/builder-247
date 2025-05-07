import time
import pytest
from prometheus_swarm.clients.web_client_nonce import WebClientNonceManager

def test_nonce_generation():
    """Test that nonce generation produces unique tokens."""
    nonce_manager = WebClientNonceManager()
    
    # Generate multiple nonces
    nonces = [nonce_manager.generate_nonce() for _ in range(100)]
    
    # Check that all nonces are unique
    assert len(set(nonces)) == 100

def test_nonce_validation():
    """Test nonce validation and consumption."""
    nonce_manager = WebClientNonceManager(nonce_expiration_seconds=5)
    
    # Generate and validate a nonce
    nonce = nonce_manager.generate_nonce()
    assert nonce_manager.validate_nonce(nonce) is True
    
    # Validate same nonce again should return False (nonce consumed)
    assert nonce_manager.validate_nonce(nonce) is False

def test_nonce_expiration():
    """Test that nonces expire after the specified time."""
    nonce_manager = WebClientNonceManager(nonce_expiration_seconds=1)
    
    nonce = nonce_manager.generate_nonce()
    assert nonce_manager.validate_nonce(nonce) is True
    
    # Wait for nonce to expire
    time.sleep(2)
    
    # Nonce should now be invalid
    assert nonce_manager.validate_nonce(nonce) is False

def test_nonce_none_validation():
    """Test validation of None or empty nonce."""
    nonce_manager = WebClientNonceManager()
    
    assert nonce_manager.validate_nonce(None) is False
    assert nonce_manager.validate_nonce('') is False

def test_nonce_manager_cleanup():
    """Test that nonce manager automatically cleans up expired nonces."""
    nonce_manager = WebClientNonceManager(nonce_expiration_seconds=1)
    
    # Generate multiple nonces
    nonces = [nonce_manager.generate_nonce() for _ in range(10)]
    
    # Wait for nonces to expire
    time.sleep(2)
    
    # Generate a new nonce, which should trigger cleanup
    nonce_manager.generate_nonce()
    
    # Validate that no old nonces remain
    for old_nonce in nonces:
        assert nonce_manager.validate_nonce(old_nonce) is False