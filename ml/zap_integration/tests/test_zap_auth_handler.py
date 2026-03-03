"""Tests for ZAPAuthenticationHandler."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch
from ml.zap_integration.zap_auth_handler import (
    ZAPAuthenticationHandler,
    ZAPAuthError,
    ZAPLoginVerificationError,
    ZAPSessionExpiredError
)


@pytest.fixture
def mock_client():
    """Create mock ZAPClient."""
    client = Mock()
    client.request = Mock(return_value={"code": "ok"})
    return client


@pytest.fixture
def auth_handler(mock_client):
    """Create ZAPAuthenticationHandler with mock client."""
    return ZAPAuthenticationHandler(client=mock_client)


def test_init_valid_client(mock_client):
    """Test initialization with valid ZAPClient."""
    handler = ZAPAuthenticationHandler(client=mock_client)
    assert handler.client == mock_client
    assert handler.db_connection is None
    assert handler._session_tokens == {}


def test_init_invalid_client():
    """Test initialization with invalid client raises TypeError."""
    with pytest.raises(TypeError):
        ZAPAuthenticationHandler(client="not a client")


def test_setup_form_auth_success(auth_handler, mock_client):
    """Test form auth setup with successful response."""
    result = auth_handler.setup_form_auth(
        context_id=1,
        login_url="http://localhost/login",
        username_field="username",
        password_field="password"
    )
    assert result is True
    mock_client.request.assert_called_once()


def test_setup_form_auth_failure(auth_handler, mock_client):
    """Test form auth setup with failed response."""
    mock_client.request.return_value = {"code": "error", "message": "Failed"}
    result = auth_handler.setup_form_auth(
        context_id=1,
        login_url="http://localhost/login",
        username_field="username",
        password_field="password"
    )
    assert result is False


def test_setup_form_based_auth_success(auth_handler, mock_client):
    """Test complete form-based auth setup."""
    with patch.object(auth_handler, 'execute_login') as mock_login, \
         patch.object(auth_handler, 'verify_login') as mock_verify, \
         patch.object(auth_handler, 'store_session_token') as mock_store:
        
        mock_login.return_value = (Mock(text="Dashboard", status_code=200), {"session_id": "abc123"})
        mock_verify.return_value = (True, "Login successful")
        mock_store.return_value = True
        
        result = auth_handler.setup_form_based_auth(
            context_id=1,
            login_url="http://localhost/login",
            username="testuser",
            password="testpass"
        )
        
        assert result is True


def test_setup_form_based_auth_login_fails(auth_handler):
    """Test form-based auth when login verification fails."""
    with patch.object(auth_handler, 'setup_form_auth', return_value=False):
        with pytest.raises(ZAPAuthError):
            auth_handler.setup_form_based_auth(
                context_id=1,
                login_url="http://localhost/login",
                username="testuser",
                password="testpass"
            )


@patch('ml.zap_integration.zap_auth_handler.requests.Session')
def test_execute_login_success(mock_session_class, auth_handler):
    """Test successful login execution."""
    mock_session = Mock()
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "Dashboard"
    mock_session.post.return_value = mock_response
    mock_session.cookies = {"sessionid": "abc123"}
    mock_session_class.return_value = mock_session
    
    response, cookies = auth_handler.execute_login(
        login_url="http://localhost/login",
        username="testuser",
        password="testpass"
    )
    
    assert response == mock_response
    assert cookies == {"sessionid": "abc123"}


@patch('ml.zap_integration.zap_auth_handler.requests.Session')
def test_execute_login_timeout(mock_session_class, auth_handler):
    """Test login timeout raises ZAPAuthError."""
    mock_session = Mock()
    mock_session.post.side_effect = __import__('requests').Timeout()
    mock_session_class.return_value = mock_session
    
    with pytest.raises(ZAPAuthError):
        auth_handler.execute_login(
            login_url="http://localhost/login",
            username="testuser",
            password="testpass"
        )


def test_verify_login_success_status_code(auth_handler):
    """Test login verification with successful status code."""
    success, message = auth_handler.verify_login(
        response_text="Some content",
        verification_string="",
        response_status=200
    )
    assert success is True


def test_verify_login_failure_status_code(auth_handler):
    """Test login verification with failed status code."""
    success, message = auth_handler.verify_login(
        response_text="Error",
        verification_string="",
        response_status=401
    )
    assert success is False
    assert "401" in message


def test_verify_login_failure_no_verification_string(auth_handler):
    """Test login verification when verification string missing."""
    success, message = auth_handler.verify_login(
        response_text="Some content without expected string",
        verification_string="dashboard",
        response_status=200
    )
    assert success is False


def test_verify_login_success_with_verification_string(auth_handler):
    """Test login verification with verification string present."""
    success, message = auth_handler.verify_login(
        response_text="Welcome to Dashboard",
        verification_string="dashboard",
        response_status=200
    )
    assert success is True


def test_store_session_token(auth_handler):
    """Test session token storage."""
    result = auth_handler.store_session_token(
        user_id="user1",
        cookie_name="sessionid",
        cookie_value="abc123",
        expires_at="2026-03-05T12:00:00"
    )
    
    assert result is True
    assert "user1" in auth_handler._session_tokens
    assert "sessionid" in auth_handler._session_tokens["user1"]


def test_retrieve_session_token_valid(auth_handler):
    """Test retrieving valid session token."""
    # Store token first
    auth_handler.store_session_token(
        user_id="user1",
        cookie_name="sessionid",
        cookie_value="abc123",
        expires_at=(datetime.now() + timedelta(hours=1)).isoformat()
    )
    
    # Retrieve token
    tokens, is_valid = auth_handler.retrieve_session_token("user1")
    
    assert is_valid is True
    assert tokens["sessionid"] == "abc123"


def test_retrieve_session_token_expired(auth_handler):
    """Test retrieving expired session token raises error."""
    # Store expired token
    auth_handler.store_session_token(
        user_id="user1",
        cookie_name="sessionid",
        cookie_value="abc123",
        expires_at=(datetime.now() - timedelta(hours=1)).isoformat()
    )
    
    # Retrieve should raise error
    with pytest.raises(ZAPSessionExpiredError):
        auth_handler.retrieve_session_token("user1")


def test_retrieve_session_token_not_found(auth_handler):
    """Test retrieving non-existent user tokens."""
    tokens, is_valid = auth_handler.retrieve_session_token("nonexistent")
    
    assert is_valid is False
    assert tokens == {}


def test_clear_expired_tokens(auth_handler):
    """Test clearing expired tokens."""
    now = datetime.now()
    
    # Store valid and expired tokens
    auth_handler.store_session_token(
        user_id="user1",
        cookie_name="valid",
        cookie_value="abc123",
        expires_at=(now + timedelta(hours=1)).isoformat()
    )
    auth_handler.store_session_token(
        user_id="user1",
        cookie_name="expired",
        cookie_value="xyz789",
        expires_at=(now - timedelta(hours=1)).isoformat()
    )
    
    # Clear expired
    count = auth_handler.clear_expired_tokens()
    
    assert count == 1
    tokens, _ = auth_handler.retrieve_session_token("user1")
    assert "valid" in tokens
    assert "expired" not in tokens


def test_create_context_user_success(auth_handler, mock_client):
    """Test creating context user."""
    result = auth_handler.create_context_user(
        context_id=1,
        user_id="user1",
        username="testuser",
        password="testpass"
    )
    
    assert result is True
    mock_client.request.assert_called_once()
