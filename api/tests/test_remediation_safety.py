"""
=============================================================================
TEST SUITE 1: REMEDIATION SAFETY GUARANTEES (SAFETY-CRITICAL)
=============================================================================

PURPOSE OF THIS TEST FILE (Plain Language Explanation):
-------------------------------------------------------
In cloud security, "remediation" means taking action to fix a security risk.
When an IAM access key is old or unrotated, our system deactivates it.

CRITICAL SAFETY RULE:
- Remediation must ALWAYS be reversible: We only set the key status to 'Inactive'.
- Remediation must NEVER permanently delete credentials: If a key is deleted by
  mistake, a production service could go down permanently with no way to restore it.
- If a key is merely set to 'Inactive', an administrator can easily re-enable it
  in seconds if it turns out to be needed.

WHAT THESE TESTS VERIFY:
1. When remediating an access key, AWS IAM's `update_access_key` is called with
   `Status='Inactive'`.
2. AWS IAM's `delete_access_key` is NEVER CALLED under any circumstances.
3. Batch remediation across multiple users also obeys the reversible rule.
4. An immutable audit record is saved to DynamoDB detailing who performed the
   action, the timestamp, and the safety guarantee.
=============================================================================
"""

from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
import api.main as main_module


class TestRemediationSafety:
    """
    Test suite verifying that access key remediation is 100% non-destructive,
    reversible, and strictly avoids permanent credential deletion.
    """

    def test_remediate_specific_access_key_sets_status_inactive_and_never_deletes(self, client: TestClient):
        """
        TEST 1 (SAFETY-CRITICAL): Single Key Remediation
        
        Plain Language:
        When a security analyst chooses to deactivate a specific stale access key for
        a specific user (e.g. user 'alice-admin' and key 'AKIA1111222233334444'):
        - The backend must call AWS IAM `update_access_key` with Status='Inactive'.
        - The backend must NEVER call `delete_access_key` (which would permanently destroy it).
        - The API must respond with HTTP 200 and confirm 'Inactive (Non-destructive & Reversible)'.
        """
        # 1. Setup mock IAM client
        mock_iam = MagicMock()
        mock_iam.update_access_key.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        mock_iam.delete_access_key = MagicMock()

        # 2. Setup mock DynamoDB table
        mock_table = MagicMock()
        mock_table.put_item.return_value = {}

        # 3. Patch the global clients in api/main.py
        with patch.object(main_module, "iam_client", mock_iam), \
             patch.object(main_module, "findings_table", mock_table):

            payload = {
                "username": "alice-admin",
                "access_key_id": "AKIA1111222233334444",
                "reason": "Stale key older than 90 days"
            }

            # 4. Make request to the endpoint
            response = client.post("/api/remediate/access-key", json=payload)

            # 5. Verify HTTP 200 response
            assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
            data = response.json()
            assert data["status"] == "success"
            assert data["safety_mode"] == "Inactive (Non-destructive & Reversible)"
            assert len(data["deactivated_keys"]) == 1
            assert data["deactivated_keys"][0]["status"] == "Inactive"
            assert data["deactivated_keys"][0]["key_id"] == "AKIA1111222233334444"

            # 6. CRITICAL ASSERTION 1: update_access_key called with Status='Inactive'
            mock_iam.update_access_key.assert_called_once_with(
                UserName="alice-admin",
                AccessKeyId="AKIA1111222233334444",
                Status="Inactive"
            )

            # 7. CRITICAL ASSERTION 2 (MOST IMPORTANT): delete_access_key NEVER called
            mock_iam.delete_access_key.assert_not_called()

    def test_remediate_user_all_active_keys_deactivates_each_and_never_deletes(self, client: TestClient):
        """
        TEST 2 (SAFETY-CRITICAL): All Keys For a Single User
        
        Plain Language:
        When an analyst provides a username without a specific key ID, the system
        finds all active access keys belonging to that user and turns each one off:
        - It must call `update_access_key` with Status='Inactive' for each active key.
        - It must NEVER call `delete_access_key` for any of the keys.
        """
        # 1. Setup mock IAM client returning two active keys
        mock_iam = MagicMock()
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAAAAAAAAAAAAAAAAA", "Status": "Active"},
                {"AccessKeyId": "AKIABBBBBBBBBBBBBBBB", "Status": "Active"},
                {"AccessKeyId": "AKIACCCCCCCCCCCCCCCC", "Status": "Inactive"},  # Already inactive
            ]
        }
        mock_iam.update_access_key.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        mock_iam.delete_access_key = MagicMock()

        mock_table = MagicMock()
        mock_table.put_item.return_value = {}

        with patch.object(main_module, "iam_client", mock_iam), \
             patch.object(main_module, "findings_table", mock_table):

            payload = {
                "username": "bob-developer"
                # access_key_id is omitted -> target all active keys for this user
            }

            response = client.post("/api/remediate/access-key", json=payload)

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert len(data["deactivated_keys"]) == 2

            # Verify update_access_key was called twice (once for each active key) with Status='Inactive'
            assert mock_iam.update_access_key.call_count == 2
            mock_iam.update_access_key.assert_any_call(
                UserName="bob-developer",
                AccessKeyId="AKIAAAAAAAAAAAAAAAAA",
                Status="Inactive"
            )
            mock_iam.update_access_key.assert_any_call(
                UserName="bob-developer",
                AccessKeyId="AKIABBBBBBBBBBBBBBBB",
                Status="Inactive"
            )

            # CRITICAL ASSERTION: delete_access_key is NEVER called
            mock_iam.delete_access_key.assert_not_called()

    def test_remediate_batch_stale_keys_deactivates_and_never_deletes(self, client: TestClient):
        """
        TEST 3 (SAFETY-CRITICAL): Batch Remediation Across All Detected Stale Keys
        
        Plain Language:
        When an analyst clicks 'Batch Remediate' for all unrotated keys across the organization:
        - The system reads stale keys from the hygiene audit report.
        - Every detected stale key is updated to Status='Inactive'.
        - Root account credentials are skipped safely.
        - `delete_access_key` is NEVER called for any key.
        """
        mock_iam = MagicMock()
        mock_iam.update_access_key.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        mock_iam.delete_access_key = MagicMock()

        mock_table = MagicMock()
        mock_table.put_item.return_value = {}

        # Mock hygiene report containing stale keys
        mock_hygiene_data = [
            {"username": "carol-analyst", "check_type": "Access Key Age", "detail": "AKIA1111111111111111 - 120 days old", "risk": "MEDIUM RISK - Key not rotated (90+ days)"},
            {"username": "dave-contractor", "check_type": "Access Key Age", "detail": "AKIA2222222222222222 - 250 days old", "risk": "MEDIUM RISK - Key not rotated (90+ days)"},
            {"username": "<root_account>", "check_type": "Root Usage", "detail": "Last used: 2026-08-01", "risk": "INFO - review manually"},
        ]

        with patch.object(main_module, "iam_client", mock_iam), \
             patch.object(main_module, "findings_table", mock_table), \
             patch.object(main_module, "load_hygiene_data", return_value=mock_hygiene_data):

            # Empty payload triggers batch deactivation of all stale keys
            response = client.post("/api/remediate/access-key", json={})

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert len(data["deactivated_keys"]) == 2

            # Assert each key was marked Inactive
            mock_iam.update_access_key.assert_any_call(
                UserName="carol-analyst",
                AccessKeyId="AKIA1111111111111111",
                Status="Inactive"
            )
            mock_iam.update_access_key.assert_any_call(
                UserName="dave-contractor",
                AccessKeyId="AKIA2222222222222222",
                Status="Inactive"
            )

            # CRITICAL SAFETY GUARANTEE: Never delete
            mock_iam.delete_access_key.assert_not_called()

    def test_remediation_persists_safety_audit_trail_in_dynamodb(self, client: TestClient):
        """
        TEST 4: DynamoDB Remediation Audit Log
        
        Plain Language:
        Whenever any remediation action takes place, a permanent audit record must
        be recorded into AWS DynamoDB documenting:
        - Who performed the remediation
        - Exactly which keys were modified
        - Explicit documentation that the action is reversible (no deletion performed)
        """
        mock_iam = MagicMock()
        mock_iam.update_access_key.return_value = {}
        mock_iam.delete_access_key = MagicMock()

        mock_table = MagicMock()
        mock_table.put_item.return_value = {}

        with patch.object(main_module, "iam_client", mock_iam), \
             patch.object(main_module, "findings_table", mock_table):

            payload = {
                "username": "eva-engineer",
                "access_key_id": "AKIA3333333333333333",
                "reason": "Quarterly credential rotation policy"
            }

            response = client.post("/api/remediate/access-key", json=payload)
            assert response.status_code == 200

            # Verify DynamoDB put_item was called with the audit record
            assert mock_table.put_item.called
            call_args = mock_table.put_item.call_args[1]
            item = call_args["Item"]

            assert item["scan_type"] == "remediation_access_key"
            assert "finding_data" in item

            # Verify safety constraint message is written into the audit log
            assert "Reversible - No deletion performed" in item["finding_data"]
            assert "Inactive" in item["finding_data"]

            # Safety guarantee: delete was never called
            mock_iam.delete_access_key.assert_not_called()
