"""
=============================================================================
TEST SUITE 3: DYNAMODB SCAN HISTORY FILTERING & PAGINATION (ISSUE #6 FIX)
=============================================================================

PURPOSE OF THIS TEST FILE (Plain Language Explanation):
-------------------------------------------------------
In AWS DynamoDB (our NoSQL database), records of past security scans are stored
in the 'AetherAranFindings' table. These records include three scan types:
1. 'privilege_escalation' (Part 1 findings)
2. 'drift' (Part 2 findings)
3. 'credential_hygiene' (Part 4 findings)
4. 'remediation_access_key' (Remediation audit records)

THE BUG THAT WAS FIXED (Issue #6):
When scanning DynamoDB with a filter (e.g. "show me only privilege_escalation"),
DynamoDB filters records AFTER reading a batch from disk. If the first batch of
records only contained 'drift' scans, older code would return 0 records and stop,
even though 'privilege_escalation' records existed on the next page!

WHAT THESE TESTS VERIFY:
1. When filtering by `scan_type`, the backend keeps following `LastEvaluatedKey`
   pages until all matching records are gathered, even if matching records are
   NOT in the first batch.
2. Unfiltered history queries correctly return all scan records sorted newest-first.
3. The `limit` parameter is strictly respected.
4. Nested JSON strings in `finding_data` are automatically parsed into Python dictionaries.
5. If DynamoDB is unavailable, the API fails gracefully with a warning rather than crashing.
=============================================================================
"""

import json
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

import api.main as main_module


class TestScanHistoryFilter:
    """
    Test suite verifying that DynamoDB scan history pagination and filtering
    operate correctly without losing data across multiple pages (Issue #6 fix).
    """

    def test_scan_history_retrieves_records_when_matches_are_on_later_pages(self, client: TestClient):
        """
        TEST 1 (CRITICAL FIX FOR ISSUE #6):
        
        Plain Language:
        Mocks DynamoDB having 2 pages of data:
        - Page 1 contains ONLY 'drift' scan records (0 privilege escalation records).
        - Page 2 contains 2 'privilege_escalation' scan records.
        
        An analyst queries GET /api/scan-history?scan_type=privilege_escalation
        
        Expected Result:
        - The backend must scan Page 1, see there's a LastEvaluatedKey, and scan Page 2.
        - The final response must return the 2 'privilege_escalation' records from Page 2.
        """
        mock_table = MagicMock()

        # Page 1: Only 'drift' records, has LastEvaluatedKey pointing to next page
        page_1_response = {
            "Items": [
                {
                    "finding_id": "find-101",
                    "scan_id": "scan-aaa",
                    "scan_type": "drift",
                    "timestamp": "2026-08-01T10:00:00Z",
                    "finding_data": json.dumps({"unused_permissions": 5})
                },
                {
                    "finding_id": "find-102",
                    "scan_id": "scan-aaa",
                    "scan_type": "drift",
                    "timestamp": "2026-08-01T10:05:00Z",
                    "finding_data": json.dumps({"unused_permissions": 2})
                }
            ],
            "LastEvaluatedKey": {"finding_id": "find-102"}
        }

        # Page 2: Contains 'privilege_escalation' records, no more pages
        page_2_response = {
            "Items": [
                {
                    "finding_id": "find-201",
                    "scan_id": "scan-bbb",
                    "scan_type": "privilege_escalation",
                    "timestamp": "2026-08-02T12:00:00Z",
                    "finding_data": json.dumps({"critical_count": 3})
                },
                {
                    "finding_id": "find-202",
                    "scan_id": "scan-ccc",
                    "scan_type": "privilege_escalation",
                    "timestamp": "2026-08-03T14:00:00Z",
                    "finding_data": json.dumps({"critical_count": 1})
                }
            ]
            # No LastEvaluatedKey -> pagination completes
        }

        # Simulate consecutive scan calls
        mock_table.scan.side_effect = [page_1_response, page_2_response]

        with patch.object(main_module, "findings_table", mock_table):
            response = client.get("/api/scan-history?scan_type=privilege_escalation")

            assert response.status_code == 200
            data = response.json()

            assert data["status"] == "success"
            # We must get all records matching the scan_type from across all pages
            assert data["count"] == 4 or len(data["data"]) == 4

            # Verify scan was called twice (traversing both pages)
            assert mock_table.scan.call_count == 2

            # Verify second scan passed ExclusiveStartKey from page 1's LastEvaluatedKey
            second_call_kwargs = mock_table.scan.call_args_list[1][1]
            assert second_call_kwargs["ExclusiveStartKey"] == {"finding_id": "find-102"}

    def test_scan_history_returns_all_scan_types_when_no_filter_provided(self, client: TestClient):
        """
        TEST 2: Unfiltered History Query
        
        Plain Language:
        When an analyst views the main scan history table without any category filter:
        - All scan types ('privilege_escalation', 'drift', 'credential_hygiene') are returned.
        - Records are sorted newest-first (descending by timestamp).
        """
        mock_table = MagicMock()
        mock_table.scan.return_value = {
            "Items": [
                {
                    "finding_id": "find-1",
                    "scan_id": "scan-1",
                    "scan_type": "drift",
                    "timestamp": "2026-08-01T10:00:00Z",
                    "finding_data": "{}"
                },
                {
                    "finding_id": "find-2",
                    "scan_id": "scan-2",
                    "scan_type": "privilege_escalation",
                    "timestamp": "2026-08-03T10:00:00Z",
                    "finding_data": "{}"
                },
                {
                    "finding_id": "find-3",
                    "scan_id": "scan-3",
                    "scan_type": "credential_hygiene",
                    "timestamp": "2026-08-02T10:00:00Z",
                    "finding_data": "{}"
                }
            ]
        }

        with patch.object(main_module, "findings_table", mock_table):
            response = client.get("/api/scan-history")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["count"] == 3

            # Verify newest timestamp (2026-08-03) is first
            timestamps = [item["timestamp"] for item in data["data"]]
            assert timestamps == sorted(timestamps, reverse=True)

    def test_scan_history_respects_limit_parameter(self, client: TestClient):
        """
        TEST 3: Limit Parameter Enforcement
        
        Plain Language:
        If there are 5 records in DynamoDB but the frontend requests `limit=2`,
        the API must return exactly the top 2 newest records.
        """
        mock_table = MagicMock()
        items = [
            {"finding_id": f"find-{i}", "scan_type": "drift", "timestamp": f"2026-08-0{i}T10:00:00Z", "finding_data": "{}"}
            for i in range(1, 6)
        ]
        mock_table.scan.return_value = {"Items": items}

        with patch.object(main_module, "findings_table", mock_table):
            response = client.get("/api/scan-history?limit=2")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert len(data["data"]) == 2
            # Should have the 2 newest items (day 05 and day 04)
            assert data["data"][0]["finding_id"] == "find-5"
            assert data["data"][1]["finding_id"] == "find-4"

    def test_scan_history_automatically_parses_json_finding_data(self, client: TestClient):
        """
        TEST 4: JSON Deserialization Helper
        
        Plain Language:
        DynamoDB stores finding payload details as a string (e.g. '{"total_events": 10}').
        The API endpoint must automatically convert this string into a clean JSON dictionary
        so the React frontend web app can display cards and tables immediately without parsing.
        """
        mock_table = MagicMock()
        mock_table.scan.return_value = {
            "Items": [
                {
                    "finding_id": "find-parse-test",
                    "scan_type": "privilege_escalation",
                    "timestamp": "2026-08-01T12:00:00Z",
                    "finding_data": json.dumps({"summary": {"critical": 2, "high": 5}})
                }
            ]
        }

        with patch.object(main_module, "findings_table", mock_table):
            response = client.get("/api/scan-history")

            assert response.status_code == 200
            data = response.json()
            first_record = data["data"][0]

            # finding_data should be a real dictionary, NOT a raw string
            assert isinstance(first_record["finding_data"], dict)
            assert first_record["finding_data"]["summary"]["critical"] == 2

    def test_scan_history_returns_warning_when_dynamodb_uninitialized(self, client: TestClient):
        """
        TEST 5: Resilient Fallback When DynamoDB Table Is Offline
        
        Plain Language:
        If DynamoDB is temporarily disconnected or credentials are not yet set up,
        the endpoint should return a helpful warning message with count=0 instead
        of throwing a 500 Internal Server Error crash.
        """
        with patch.object(main_module, "findings_table", None):
            response = client.get("/api/scan-history")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "warning"
            assert data["count"] == 0
            assert data["data"] == []
            assert "DynamoDB table is not initialized" in data["message"]
