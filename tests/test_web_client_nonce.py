import os
import time
import pytest
import requests
import requests_mock
from src.web_client_nonce import WebClientNonceRetriever

@pytest.fixture
def mock_nonce_endpoint():
    return 'https://test-nonce-service.com/nonce'

@pytest.fixture
def nonce_retriever(mock_nonce_endpoint):
    return WebClientNonceRetriever(nonce_endpoint=mock_nonce_endpoint)

def test_nonce_retrieval_success(mock_nonce_endpoint):
    """Test successful nonce retrieval."""
    with requests_mock.Mocker() as m:
        m.get(mock_nonce_endpoint, json={'nonce': 'test_nonce_123'})
        retriever = WebClientNonceRetriever(nonce_endpoint=mock_nonce_endpoint)
        nonce = retriever.get_nonce()
        assert nonce == 'test_nonce_123'

def test_nonce_retrieval_failure(mock_nonce_endpoint):
    """Test nonce retrieval with network failures."""
    with requests_mock.Mocker() as m:
        m.get(mock_nonce_endpoint, status_code=500)
        retriever = WebClientNonceRetriever(nonce_endpoint=mock_nonce_endpoint)
        nonce = retriever.get_nonce()
        assert nonce is None

def test_nonce_exponential_backoff(mock_nonce_endpoint):
    """Test exponential backoff during network failures."""
    with requests_mock.Mocker() as m:
        m.get(mock_nonce_endpoint, [
            {'status_code': 500},
            {'status_code': 500},
            {'json': {'nonce': 'backoff_nonce'}}
        ])
        retriever = WebClientNonceRetriever(nonce_endpoint=mock_nonce_endpoint)
        start_time = time.time()
        nonce = retriever.get_nonce()
        total_time = time.time() - start_time
        
        assert nonce == 'backoff_nonce'
        assert total_time >= 3.0  # Approximately 1 + 2 seconds of waiting

def test_nonce_validation(nonce_retriever):
    """Test nonce validation mechanism."""
    with requests_mock.Mocker() as m:
        m.get(nonce_retriever.nonce_endpoint, json={'nonce': 'valid_nonce'})
        nonce = nonce_retriever.get_nonce()
        
        assert nonce_retriever.validate_nonce(nonce) is True
        
        # Simulate expired nonce
        time.sleep(310)  # More than max age
        assert nonce_retriever.validate_nonce(nonce) is False

def test_nonce_caching(mock_nonce_endpoint):
    """Test nonce caching behavior."""
    with requests_mock.Mocker() as m:
        m.get(mock_nonce_endpoint, json={'nonce': 'cached_nonce'})
        retriever = WebClientNonceRetriever(nonce_endpoint=mock_nonce_endpoint)
        
        first_nonce = retriever.get_nonce()
        second_nonce = retriever.get_nonce()
        
        assert first_nonce == second_nonce

def test_performance_nonce_retrieval(mock_nonce_endpoint):
    """Test nonce retrieval performance."""
    with requests_mock.Mocker() as m:
        m.get(mock_nonce_endpoint, json={'nonce': 'perf_nonce'})
        retriever = WebClientNonceRetriever(nonce_endpoint=mock_nonce_endpoint)
        
        retrieval_times = []
        for _ in range(10):
            start_time = time.time()
            nonce = retriever.get_nonce()
            retrieval_time = time.time() - start_time
            retrieval_times.append(retrieval_time)
        
        # Verify 95% of requests under 200ms
        assert sum(t <= 0.2 for t in retrieval_times) >= 9