"""
Shared fixtures for the AETHER ARAN IAM test suite.

`import app` works from here because app.py wraps ALL Streamlit page
rendering inside `main()`, guarded by `if __name__ == "__main__":` — see
app.py. Importing the module only defines functions/classes; it never
calls st.set_page_config(), the auth gate, or renders anything.
"""

import sys
from pathlib import Path

import pytest
import pandas as pd

# Make "part 1" (where app.py lives) importable as `app`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402


@pytest.fixture
def events_df():
    """Sample CloudTrail IAM events, matching IAM_EVENT_SCHEMA."""
    return pd.DataFrame([
        {"username": "alice", "event": "AttachUserPolicy", "policy": "AdministratorAccess",
         "risk_level": "CRITICAL", "time": "2026-08-01T10:00:00Z", "source_ip": "10.0.0.1"},
        {"username": "bob", "event": "CreateAccessKey", "policy": "N/A",
         "risk_level": "HIGH", "time": "2026-08-02T11:00:00Z", "source_ip": "10.0.0.2"},
        {"username": "carol", "event": "PutUserPolicy", "policy": "ReadOnlyAccess",
         "risk_level": "MEDIUM", "time": "2026-08-03T12:00:00Z", "source_ip": "10.0.0.3"},
        {"username": "dave", "event": "ListBuckets", "policy": "N/A",
         "risk_level": "LOW", "time": "2026-08-04T13:00:00Z", "source_ip": "10.0.0.4"},
    ])


@pytest.fixture
def drift_df():
    """Sample Least-Privilege Drift Analyzer report."""
    return pd.DataFrame([
        {"username": "alice", "permission": "s3:DeleteBucket", "status": "NEVER USED", "risk": "HIGH RISK - unused"},
        {"username": "bob", "permission": "ec2:StopInstances", "status": "USED", "risk": "MEDIUM RISK - rarely used"},
        {"username": "carol", "permission": "iam:ListUsers", "status": "USED", "risk": "LOW RISK"},
    ])


@pytest.fixture
def hygiene_df():
    """Sample Credential Hygiene report."""
    return pd.DataFrame([
        {"username": "alice", "mfa_enabled": False, "key_age_days": 400, "risk": "HIGH RISK - No MFA"},
        {"username": "bob", "mfa_enabled": True, "key_age_days": 200, "risk": "MEDIUM RISK - key not rotated"},
        {"username": "carol", "mfa_enabled": True, "key_age_days": 10, "risk": "INFO - all clear"},
    ])
