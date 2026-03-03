"""Tests for ZAPSpiderManager."""

import pytest
import time
from unittest.mock import Mock, MagicMock, patch
from ml.zap_integration.zap_spider_manager import (
    ZAPSpiderManager,
    ZAPSpiderError,
    ZAPSpiderTimeoutError
)


@pytest.fixture
def mock_client():
    """Create mock ZAPClient."""
    client = Mock()
    return client


@pytest.fixture
def spider_manager(mock_client):
    """Create ZAPSpiderManager with mock client."""
    return ZAPSpiderManager(client=mock_client)


def test_init_valid_client(mock_client):
    """Test initialization with valid client."""
    manager = ZAPSpiderManager(client=mock_client)
    assert manager.client == mock_client
    assert manager._spider_jobs == {}


def test_init_invalid_client():
    """Test initialization with invalid client raises TypeError."""
    with pytest.raises(TypeError):
        ZAPSpiderManager(client="not a client")


def test_start_spider_success(spider_manager, mock_client):
    """Test successful spider start."""
    mock_client.request.return_value = {"id": "123"}
    
    scan_id, start_time = spider_manager.start_spider(
        url="http://localhost/app",
        depth=3
    )
    
    assert scan_id == "123"
    assert isinstance(start_time, float)
    assert "123" in spider_manager._spider_jobs


def test_start_spider_failure(spider_manager, mock_client):
    """Test spider start failure."""
    mock_client.request.return_value = {"error": "Failed"}
    
    with pytest.raises(ZAPSpiderError):
        spider_manager.start_spider(url="http://localhost/app")


def test_get_progress_success(spider_manager, mock_client):
    """Test getting spider progress."""
    mock_client.request.return_value = {
        "status": 75,
        "spider": {"pages": 50}
    }
    
    progress = spider_manager.get_progress(scan_id="123")
    
    assert progress["progress"] == 75
    assert progress["pages_found"] == 50
    assert progress["id"] == "123"


def test_get_progress_invalid_scan(spider_manager, mock_client):
    """Test getting progress for invalid scan ID."""
    mock_client.request.return_value = {"error": "Scan not found"}
    
    with pytest.raises(ZAPSpiderError):
        spider_manager.get_progress(scan_id="invalid")


def test_wait_for_completion_success(spider_manager, mock_client):
    """Test waiting for spider completion."""
    # Mock progress: 0% → 50% → 100%
    mock_client.request.side_effect = [
        {"status": 0, "spider": {"pages": 0}},  # get_progress call 1
        {"status": 50, "spider": {"pages": 25}},  # get_progress call 2
        {"status": 100, "spider": {"pages": 50}},  # get_progress call 3
        ["http://example.com/1", "http://example.com/2"]  # get_discovered_urls
    ]
    
    # Start spider first
    spider_manager._spider_jobs["123"] = {
        "url": "http://localhost",
        "start_time": time.time(),
        "status": "Running"
    }
    
    with patch('ml.zap_integration.zap_spider_manager.time.sleep'):
        success, urls, duration = spider_manager.wait_for_completion(
            scan_id="123",
            timeout_minutes=30,
            poll_interval=1
        )
    
    assert success is True
    assert len(urls) > 0
    assert duration > 0


def test_wait_for_completion_timeout(spider_manager, mock_client):
    """Test spider timeout."""
    mock_client.request.return_value = {"status": 20, "spider": {"pages": 10}}
    
    spider_manager._spider_jobs["123"] = {
        "url": "http://localhost",
        "start_time": time.time(),
        "status": "Running"
    }
    
    with patch('ml.zap_integration.zap_spider_manager.time.time') as mock_time, \
         patch('ml.zap_integration.zap_spider_manager.time.sleep'):
        
        # Simulate timeout
        mock_time.side_effect = [time.time(), time.time() + 2000]  # 2000 seconds > 60 second timeout
        
        with pytest.raises(ZAPSpiderTimeoutError):
            spider_manager.wait_for_completion(
                scan_id="123",
                timeout_minutes=1,
                poll_interval=1
            )


def test_get_discovered_urls_success(spider_manager, mock_client):
    """Test retrieving discovered URLs."""
    urls = [
        "http://example.com/page1",
        "http://example.com/page2",
        "http://example.com/page1"  # duplicate
    ]
    mock_client.request.return_value = urls
    
    result = spider_manager.get_discovered_urls(scan_id="123")
    
    assert len(result) == 2  # Duplicates removed
    assert "http://example.com/page1" in result
    assert "http://example.com/page2" in result


def test_get_discovered_urls_empty(spider_manager, mock_client):
    """Test retrieving URLs when spider found nothing."""
    mock_client.request.return_value = []
    
    result = spider_manager.get_discovered_urls(scan_id="123")
    
    assert result == []


def test_get_discovered_urls_error(spider_manager, mock_client):
    """Test error retrieving URLs."""
    mock_client.request.return_value = {"error": "Scan not found"}
    
    with pytest.raises(ZAPSpiderError):
        spider_manager.get_discovered_urls(scan_id="invalid")


def test_get_spider_status_success(spider_manager, mock_client):
    """Test getting detailed spider status."""
    mock_client.request.return_value = {
        "status": 100,
        "spider": {"pages": 50}
    }
    
    spider_manager._spider_jobs["123"] = {
        "url": "http://example.com",
        "start_time": time.time() - 100,  # Started 100 seconds ago
        "status": "Running"
    }
    
    status = spider_manager.get_spider_status(scan_id="123")
    
    assert status["id"] == "123"
    assert status["progress"] == 100
    assert status["pages_found"] == 50
    assert status["duration_seconds"] >= 100
    assert status["url"] == "http://example.com"


def test_stop_spider_success(spider_manager, mock_client):
    """Test stopping spider."""
    mock_client.request.return_value = {"code": "ok"}
    
    spider_manager._spider_jobs["123"] = {
        "url": "http://example.com",
        "start_time": time.time(),
        "status": "Running"
    }
    
    result = spider_manager.stop_spider(scan_id="123")
    
    assert result is True
    assert spider_manager._spider_jobs["123"]["status"] == "Stopped"


def test_stop_spider_failure(spider_manager, mock_client):
    """Test stopping spider fails gracefully."""
    mock_client.request.return_value = {"error": "Failed"}
    
    result = spider_manager.stop_spider(scan_id="invalid")
    
    assert result is False


def test_pause_spider_success(spider_manager, mock_client):
    """Test pausing spider."""
    mock_client.request.return_value = {"code": "ok"}
    
    spider_manager._spider_jobs["123"] = {
        "url": "http://example.com",
        "start_time": time.time(),
        "status": "Running"
    }
    
    result = spider_manager.pause_spider(scan_id="123")
    
    assert result is True
    assert spider_manager._spider_jobs["123"]["status"] == "Paused"


def test_resume_spider_success(spider_manager, mock_client):
    """Test resuming spider."""
    mock_client.request.return_value = {"code": "ok"}
    
    spider_manager._spider_jobs["123"] = {
        "url": "http://example.com",
        "start_time": time.time(),
        "status": "Paused"
    }
    
    result = spider_manager.resume_spider(scan_id="123")
    
    assert result is True
    assert spider_manager._spider_jobs["123"]["status"] == "Running"


def test_progress_callback(spider_manager, mock_client):
    """Test progress callback is called."""
    callback_calls = []
    
    def progress_callback(progress):
        callback_calls.append(progress)
    
    mock_client.request.side_effect = [
        {"status": 100, "spider": {"pages": 50}},
        ["http://example.com"]
    ]
    
    spider_manager._spider_jobs["123"] = {
        "url": "http://localhost",
        "start_time": time.time(),
        "status": "Running"
    }
    
    with patch('ml.zap_integration.zap_spider_manager.time.sleep'):
        success, urls, duration = spider_manager.wait_for_completion(
            scan_id="123",
            progress_callback=progress_callback
        )
    
    assert len(callback_calls) > 0
    assert callback_calls[0]["id"] == "123"
