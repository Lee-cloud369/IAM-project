"""
=============================================================================
AETHER ARAN IAM - TEST SUITE CONFIGURATION & SHARED FIXTURES
=============================================================================

This file provides shared testing helpers (fixtures) for all tests in api/tests/.
It sets up:
1. Python path configuration so all backend and core modules can be imported.
2. A FastAPI TestClient that simulates web browser requests to our API.
3. Authentication bypass (dependency override) so tests can run without real
   AWS Cognito login credentials.
4. Clean mock objects for AWS IAM, AWS S3, and AWS DynamoDB.
=============================================================================
"""

import os
import sys
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# 1. CONFIGURE PYTHON PATHS
# ---------------------------------------------------------------------------
# Project root directory: "d:/IAM project"
BASE_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = BASE_DIR / "api"
PART1_DIR = BASE_DIR / "part 1"
PART2_DIR = BASE_DIR / "part 2"
PART4_DIR = BASE_DIR / "part 4"

for path in [BASE_DIR, API_DIR, PART1_DIR, PART2_DIR, PART4_DIR]:
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

# Ensure AWS dummy credentials so boto3 never attempts real network calls
os.environ["AWS_ACCESS_KEY_ID"] = "testing-mock-key-id"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing-mock-secret-key"
os.environ["AWS_SECURITY_TOKEN"] = "testing-mock-token"
os.environ["AWS_SESSION_TOKEN"] = "testing-mock-session-token"
os.environ["AWS_DEFAULT_REGION"] = "ap-south-1"
os.environ["AWS_REGION"] = "ap-south-1"

# Import FastAPI application and token verification dependency
from api.main import app, verify_cognito_token, limiter  # noqa: E402


# ---------------------------------------------------------------------------
# 2. FIXTURES FOR AUTHENTICATION & FASTAPI TEST CLIENT
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def disable_rate_limiting():
    """
    Temporarily disables SlowAPI rate limiting during test runs so automated
    tests running quickly in succession are not throttled with 429 errors.
    """
    original_enabled = limiter.enabled
    limiter.enabled = False
    yield
    limiter.enabled = original_enabled


@pytest.fixture
def mock_authenticated_user():
    """
    Returns a mock user payload representing a verified security analyst.
    This replaces real AWS Cognito JWT tokens during automated tests.
    """
    return {
        "sub": "mock-analyst-uuid-12345",
        "email": "security-analyst@aetheraran.io",
        "username": "sec-analyst",
        "token_use": "access",
        "cognito:username": "sec-analyst",
        "_raw_token": "mock.jwt.token"
    }


@pytest.fixture
def client(mock_authenticated_user) -> Generator[TestClient, None, None]:
    """
    Creates a FastAPI TestClient with AWS Cognito authentication mocked.
    Any request made with this client will automatically be treated as authenticated.
    """
    app.dependency_overrides[verify_cognito_token] = lambda: mock_authenticated_user
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def mock_iam_client():
    """
    Creates a mock AWS IAM boto3 client with standard methods.
    """
    mock = MagicMock()
    mock.update_access_key.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}
    mock.list_access_keys.return_value = {"AccessKeyMetadata": []}
    mock.list_users.return_value = {"Users": []}
    mock.delete_access_key = MagicMock()
    return mock


@pytest.fixture
def mock_dynamodb_table():
    """
    Creates a mock AWS DynamoDB Table object with put_item and scan methods.
    """
    mock_table = MagicMock()
    mock_table.put_item.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}
    mock_table.scan.return_value = {"Items": [], "Count": 0}
    return mock_table
