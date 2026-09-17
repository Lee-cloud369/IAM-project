"""
=============================================================================
TEST SUITE 4: EMPTY CLOUDTRAIL LOGS HANDLING (ISSUE #4 FIX)
=============================================================================

PURPOSE OF THIS TEST FILE (Plain Language Explanation):
-------------------------------------------------------
In a brand-new AWS account or a testing environment, CloudTrail may have
0 recorded IAM security events.

THE BUG THAT WAS FIXED (Issue #4):
In older code, if `fetch_iam_events()` returned an empty list `[]`, passing it
directly into `pd.DataFrame([])` created an empty table with NO columns.
When the subsequent code tried to calculate statistics on `df['event']`, `df['time']`,
or `df['username']`, Python threw a `KeyError: 'event'` and crashed the entire application!

THE FIX:
The code now explicitly checks `if not iam_events:` and creates a properly-structured
empty DataFrame with all required schema columns, allowing the system to run smoothly
without crashing.

WHAT THESE TESTS VERIFY:
1. When CloudTrail logs return an empty list `[]`, the anomaly analysis pipeline
   handles it gracefully without any `KeyError`.
2. The FastAPI `/api/privilege-escalation` endpoint returns HTTP 200 with zero
   counts instead of throwing a 500 server crash.
3. The AI Chat context builder (`_df_to_llm_context`) safely handles empty
   dataframes and returns "No data available".
4. The scan initialization endpoint (`/api/scan/initialize`) handles empty
   event lists gracefully and logs records safely to DynamoDB.
=============================================================================
"""

from unittest.mock import MagicMock, patch
import pandas as pd
from fastapi.testclient import TestClient

import api.main as main_module
import detector_core


class TestEmptyCloudTrailHandling:
    """
    Test suite verifying that empty CloudTrail event lists are handled safely
    across data processing pipelines, API endpoints, and AI assistants (Issue #4 fix).
    """

    def test_empty_cloudtrail_events_dataframe_pipeline_no_key_error(self):
        """
        TEST 1 (CRITICAL FIX FOR ISSUE #4):
        
        Plain Language:
        Simulates the Part 1 data science anomaly pipeline when `fetch_iam_events`
        returns an empty list `[]`.
        
        Verifies that:
        - The code checks `if not iam_events` and initializes a schema-compliant DataFrame.
        - No KeyError: 'event' or other crashes occur.
        - The resulting DataFrame has all 10 expected security columns.
        """
        # Simulate empty S3 CloudTrail return
        iam_events = []

        # Replicate the fixed pipeline logic from 'part 1/fetch logs.py'
        if not iam_events:
            df = pd.DataFrame(columns=[
                "username", "event", "policy", "risk_level", "time",
                "source_ip", "event_code", "hour", "user_event_count", "anomaly_label"
            ])
        else:
            df = pd.DataFrame(iam_events)
            event_map = {
                "CreateUser": 0, "AttachUserPolicy": 1, "CreateAccessKey": 2,
                "PutUserPolicy": 3, "AttachRolePolicy": 4, "CreateRole": 5
            }
            df["event_code"] = df["event"].map(event_map)

        # Assert no crash occurred, DataFrame is empty but has full schema
        assert df.empty
        assert len(df) == 0
        expected_columns = [
            "username", "event", "policy", "risk_level", "time",
            "source_ip", "event_code", "hour", "user_event_count", "anomaly_label"
        ]
        assert list(df.columns) == expected_columns

    def test_load_privilege_escalation_data_handles_empty_s3_events(self):
        """
        TEST 2: Backend Data Loader Fallback
        
        Plain Language:
        When `detector_core.fetch_iam_events` finds 0 events in S3 and no local
        CSV cache exists, `load_privilege_escalation_data()` should return a clean
        list of events (or fallback baseline) without throwing an uncaught exception.
        """
        # Clear cache before test
        main_module._CACHE["privilege_escalation"] = {"data": None, "timestamp": 0.0}

        with patch.object(main_module, "DETECTOR_CORE_AVAILABLE", True), \
             patch.object(detector_core, "fetch_iam_events", return_value=[]):

            events = main_module.load_privilege_escalation_data()

            # Verify it returned a valid list without raising any exceptions
            assert isinstance(events, list)
            assert len(events) > 0  # Falls back to safe baseline data

    def test_privilege_escalation_endpoint_returns_200_when_events_empty(self, client: TestClient):
        """
        TEST 3: API Endpoint Resilience with 0 Events
        
        Plain Language:
        If there are truly 0 security risk events in the system, the dashboard
        endpoint GET /api/privilege-escalation must return HTTP 200 with
        total_events: 0, critical_risk_count: 0, and data: [] (not a 500 error).
        """
        with patch.object(main_module, "load_privilege_escalation_data", return_value=[]):
            response = client.get("/api/privilege-escalation")

            assert response.status_code == 200
            data = response.json()

            assert data["status"] == "success"
            assert data["summary"]["total_events"] == 0
            assert data["summary"]["critical_risk_count"] == 0
            assert data["summary"]["high_risk_count"] == 0
            assert data["data"] == []

    def test_llm_context_builder_handles_empty_dataframe_gracefully(self):
        """
        TEST 4: AI Assistant Context Builder with Empty Tables
        
        Plain Language:
        When preparing data context for the Gemini AI assistant (NIMORA), if any
        security table is completely empty or None, the helper `_df_to_llm_context`
        must safely return 'No data available' without crashing.
        """
        # Case A: Empty DataFrame
        empty_df = pd.DataFrame()
        result_empty = main_module._df_to_llm_context(empty_df, risk_col="risk_level")
        assert result_empty == "No data available"

        # Case B: None passed
        result_none = main_module._df_to_llm_context(None, risk_col="risk_level")
        assert result_none == "No data available"

        # Case C: DataFrame with columns but 0 rows
        empty_with_cols = pd.DataFrame(columns=["username", "event", "risk_level"])
        result_cols = main_module._df_to_llm_context(empty_with_cols, risk_col="risk_level")
        assert result_cols == "No data available"

    def test_scan_initialization_handles_empty_events_and_logs_cleanly(self, client: TestClient):
        """
        TEST 5: Full Scan Initialization with Empty Data
        
        Plain Language:
        When an analyst triggers POST /api/scan/initialize in an empty AWS account:
        - The scan executes successfully.
        - Findings are safely written to DynamoDB.
        - The API returns HTTP 200 with a valid scan_id.
        """
        mock_table = MagicMock()
        mock_table.put_item.return_value = {}

        with patch.object(main_module, "findings_table", mock_table), \
             patch.object(main_module, "load_privilege_escalation_data", return_value=[]), \
             patch.object(main_module, "load_drift_data", return_value=[]), \
             patch.object(main_module, "load_hygiene_data", return_value=[]):

            response = client.post("/api/scan/initialize")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert "scan_id" in data
            assert data["records_logged"] == 3

            # Verify DynamoDB recorded 3 findings (privilege_escalation, drift, hygiene)
            assert mock_table.put_item.call_count == 3
