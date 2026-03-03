"""Integration tests for complete ZAP pipeline."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from ml.zap_integration.zap_integration_manager import ZAPIntegrationManager


@pytest.fixture
def mock_zap_manager():
    """Create mock ZAPIntegrationManager."""
    with patch('ml.zap_integration.zap_integration_manager.ZAPClient'), \
         patch('ml.zap_integration.zap_integration_manager.ZAPAuthenticationHandler'), \
         patch('ml.zap_integration.zap_integration_manager.ZAPSpiderManager'), \
         patch('ml.zap_integration.zap_integration_manager.ZAPActiveScanManager'), \
         patch('ml.zap_integration.zap_integration_manager.ZAPResultAggregator'):
        
        manager = ZAPIntegrationManager()
        
        # Mock all components
        manager.client.get_status = Mock(return_value={"status": "connected"})
        manager.spider_manager.start_spider = Mock(return_value=("spider_scan_1", 100.0))
        manager.spider_manager.wait_for_completion = Mock(
            return_value=(True, ["http://target/page1", "http://target/page2"], 30.0)
        )
        manager.ascan_manager.start_ascan = Mock(return_value=("ascan_scan_1", 100.0))
        manager.ascan_manager.wait_for_scan_completion = Mock(
            return_value=(True, [
                {"id": "1", "type": "SQL Injection", "risk": "High", "url": "http://target/page1"},
                {"id": "2", "type": "XSS", "risk": "Medium", "url": "http://target/page2"}
            ], 60.0)
        )
        manager.result_aggregator.aggregate_and_filter = Mock(
            return_value={
                "input_count": 2,
                "tier1_removed": 0,
                "tier2_removed": 0,
                "tier3_removed": 0,
                "output_count": 2,
                "filtered_findings": [
                    {"id": "1", "category": "SQL Injection", "severity": "High"},
                    {"id": "2", "category": "XSS", "severity": "Medium"}
                ],
                "statistics": {"filtering_percentage": 0.0}
            }
        )
        
        yield manager


def test_integration_complete_workflow(mock_zap_manager):
    """Test complete unauthenticated scan workflow."""
    result = mock_zap_manager.scan_unauthenticated(
        target_url="http://target.com",
        spider_depth=2,
        scan_policy="medium"
    )
    
    assert result["success"] is True
    assert result["total_findings"] == 2
    assert result["filtered_findings"] == 2
    assert len(result["alerts"]) == 2
    assert result["duration_seconds"] > 0


def test_integration_with_authentication(mock_zap_manager):
    """Test authenticated scan workflow."""
    mock_zap_manager.auth_handler.setup_form_based_auth = Mock(return_value=True)
    
    result = mock_zap_manager.scan_with_authentication(
        target_url="http://moodle.local",
        spider_depth=2,
        scan_policy="medium",
        username="admin",
        password="password"
    )
    
    assert result["success"] is True
    mock_zap_manager.auth_handler.setup_form_based_auth.assert_called_once()


def test_integration_initialization(mock_zap_manager):
    """Test manager initialization."""
    assert mock_zap_manager.initialize() is True
    mock_zap_manager.client.get_status.assert_called_once()


def test_integration_spider_phase(mock_zap_manager):
    """Test spider phase independently."""
    mock_zap_manager.spider_manager.start_spider = Mock(return_value=("scan1", 100.0))
    
    scan_id, urls = mock_zap_manager.spider_target(
        target_url="http://target.com",
        depth=2
    )
    
    assert scan_id == "scan1" or urls is not None
    assert isinstance(urls, list)


def test_integration_scan_phase(mock_zap_manager):
    """Test active scan phase independently."""
    mock_zap_manager.ascan_manager.start_ascan = Mock(return_value=("scan2", 100.0))
    
    urls = ["http://target/page1", "http://target/page2"]
    scan_id, alerts = mock_zap_manager.scan_discovered_urls(
        urls=urls,
        context_id=1,
        user_id=1,
        scan_policy="medium"
    )
    
    assert len(alerts) > 0


def test_integration_filter_phase(mock_zap_manager):
    """Test filtering phase independently."""
    findings = [
        {"id": "1", "type": "SQL Injection", "risk": "High"},
        {"id": "2", "type": "Info Disclosure", "risk": "Informational"}
    ]
    
    result = mock_zap_manager.filter_results(findings, apply_ml=True)
    
    assert "filtered_findings" in result
    assert "statistics" in result


def test_integration_error_handling(mock_zap_manager):
    """Test error handling in workflow."""
    mock_zap_manager.spider_manager.start_spider = Mock(side_effect=Exception("Spider failed"))
    
    with pytest.raises(Exception):
        mock_zap_manager.spider_target("http://target.com")


def test_integration_moodle_auth_config(mock_zap_manager):
    """Test Moodle authentication configuration."""
    mock_zap_manager.auth_handler.setup_form_based_auth = Mock(return_value=True)
    
    result = mock_zap_manager.configure_moodle_auth(
        context_id=1,
        moodle_url="http://moodle.local",
        username="admin",
        password="password"
    )
    
    assert result is True
    mock_zap_manager.auth_handler.setup_form_based_auth.assert_called_once()
    call_args = mock_zap_manager.auth_handler.setup_form_based_auth.call_args
    assert "/login/index.php" in call_args[1]["login_url"]
