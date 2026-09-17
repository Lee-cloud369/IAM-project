"""
=============================================================================
TEST SUITE 2: AWS API PAGINATION FIXES
=============================================================================

PURPOSE OF THIS TEST FILE (Plain Language Explanation):
-------------------------------------------------------
When asking AWS for data (like "list all users" or "list all files in an S3 bucket"),
AWS rarely sends all results in a single response if you have a lot of items.
Instead, AWS sends them in chunks called "pages" (e.g., 100 or 1000 items per page).

THE BUG THAT WAS FIXED:
In older versions, code might only read the first page of results and stop,
silently ignoring all users or log files on page 2, page 3, etc. This meant
security risks for users on later pages were completely invisible!

WHAT THESE TESTS VERIFY:
1. `drift_analyzer.get_all_users()` in Part 2 correctly asks AWS IAM for all pages
   and collects every single user across all pages.
2. `hygiene_checker.get_all_users()` in Part 4 correctly paginates and collects
   every user across all pages.
3. `detector_core.fetch_iam_events()` in Part 1 correctly paginates through AWS S3
   `list_objects_v2` and processes CloudTrail log files from every page.
=============================================================================
"""

import io
import gzip
import json
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

import drift_analyzer
import hygiene_checker
import detector_core


def _make_gzipped_cloudtrail_body(records):
    """Helper to create a realistic in-memory gzipped CloudTrail JSON response."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(json.dumps({"Records": records}).encode("utf-8"))
    buf.seek(0)
    return {"Body": buf}


class TestBoto3PaginationFixes:
    """
    Test suite verifying that all AWS SDK (boto3) data retrieval functions
    correctly traverse multi-page paginated responses.
    """

    def test_iam_list_users_pagination_in_drift_analyzer(self):
        """
        TEST 1: IAM User Pagination in Least-Privilege Drift Analyzer (Part 2)
        
        Plain Language:
        Mocks AWS IAM returning 2 pages of users:
        - Page 1 contains: 'user-alice' and 'user-bob'
        - Page 2 contains: 'user-carol' and 'user-dave'
        
        Verifies that get_all_users() returns all 4 users, confirming the
        paginator fix works and no users are skipped.
        """
        mock_iam = MagicMock()
        mock_paginator = MagicMock()

        # Define 2 separate pages of IAM users
        page_1 = {"Users": [{"UserName": "user-alice", "Arn": "arn:aws:iam::123:user/user-alice"},
                             {"UserName": "user-bob", "Arn": "arn:aws:iam::123:user/user-bob"}]}
        page_2 = {"Users": [{"UserName": "user-carol", "Arn": "arn:aws:iam::123:user/user-carol"},
                             {"UserName": "user-dave", "Arn": "arn:aws:iam::123:user/user-dave"}]}

        mock_paginator.paginate.return_value = [page_1, page_2]
        mock_iam.get_paginator.return_value = mock_paginator

        with patch.object(drift_analyzer, "iam", mock_iam):
            users = drift_analyzer.get_all_users()

            # Verify paginator was requested for 'list_users'
            mock_iam.get_paginator.assert_called_once_with("list_users")

            # Verify we collected all 4 users across both pages
            assert len(users) == 4, f"Expected 4 users across 2 pages, but got {len(users)}"
            user_names = [u["UserName"] for u in users]
            assert user_names == ["user-alice", "user-bob", "user-carol", "user-dave"]

    def test_iam_list_users_pagination_in_hygiene_checker(self):
        """
        TEST 2: IAM User Pagination in Credential Hygiene Checker (Part 4)
        
        Plain Language:
        Mocks AWS IAM returning 3 pages of users:
        - Page 1: 1 user ('analyst-1')
        - Page 2: 1 user ('analyst-2')
        - Page 3: 1 user ('analyst-3')
        
        Verifies that hygiene_checker.get_all_users() collects all 3 users.
        """
        mock_iam = MagicMock()
        mock_paginator = MagicMock()

        page_1 = {"Users": [{"UserName": "analyst-1", "Arn": "arn:aws:iam::123:user/analyst-1"}]}
        page_2 = {"Users": [{"UserName": "analyst-2", "Arn": "arn:aws:iam::123:user/analyst-2"}]}
        page_3 = {"Users": [{"UserName": "analyst-3", "Arn": "arn:aws:iam::123:user/analyst-3"}]}

        mock_paginator.paginate.return_value = [page_1, page_2, page_3]
        mock_iam.get_paginator.return_value = mock_paginator

        with patch.object(hygiene_checker, "iam", mock_iam):
            users = hygiene_checker.get_all_users()

            mock_iam.get_paginator.assert_called_once_with("list_users")
            assert len(users) == 3
            user_names = [u["UserName"] for u in users]
            assert user_names == ["analyst-1", "analyst-2", "analyst-3"]

    def test_s3_list_objects_v2_pagination_in_detector_core(self):
        """
        TEST 3: S3 Bucket Log File Pagination in Privilege Escalation Detector (Part 1)
        
        Plain Language:
        Mocks AWS S3 returning CloudTrail logs spread across 2 pages:
        - Page 1 contains 'AWSLogs/account/file1.json.gz' (with AttachUserPolicy event)
        - Page 2 contains 'AWSLogs/account/file2.json.gz' (with CreateAccessKey event)
        
        Verifies that detector_core.fetch_iam_events() reads files from both pages
        and extracts both security risk events.
        """
        mock_s3 = MagicMock()
        mock_paginator = MagicMock()

        # Page 1 has file1, Page 2 has file2
        page_1 = {"Contents": [{"Key": "AWSLogs/123/file1.json.gz"}]}
        page_2 = {"Contents": [{"Key": "AWSLogs/123/file2.json.gz"}]}
        mock_paginator.paginate.return_value = [page_1, page_2]
        mock_s3.get_paginator.return_value = mock_paginator

        # Event in file 1
        event_file_1 = [
            {
                "eventName": "AttachUserPolicy",
                "eventTime": "2026-08-01T10:00:00Z",
                "sourceIPAddress": "192.168.1.1",
                "userIdentity": {"userName": "alice-admin"},
                "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
            }
        ]

        # Event in file 2
        event_file_2 = [
            {
                "eventName": "CreateAccessKey",
                "eventTime": "2026-08-02T11:00:00Z",
                "sourceIPAddress": "192.168.1.2",
                "userIdentity": {"userName": "bob-dev"},
                "requestParameters": {}
            }
        ]

        # Return different gzipped content based on the requested file Key
        def mock_get_object(Bucket, Key):
            if Key == "AWSLogs/123/file1.json.gz":
                return _make_gzipped_cloudtrail_body(event_file_1)
            elif Key == "AWSLogs/123/file2.json.gz":
                return _make_gzipped_cloudtrail_body(event_file_2)
            raise ValueError(f"Unexpected Key: {Key}")

        mock_s3.get_object.side_effect = mock_get_object

        with patch("boto3.client", return_value=mock_s3):
            events = detector_core.fetch_iam_events("mock-cloudtrail-bucket")

            # Verify paginator was requested for 'list_objects_v2' with prefix 'AWSLogs/'
            mock_s3.get_paginator.assert_called_once_with("list_objects_v2")
            mock_paginator.paginate.assert_called_once_with(
                Bucket="mock-cloudtrail-bucket",
                Prefix="AWSLogs/"
            )

            # Verify events from BOTH pages were parsed successfully
            assert len(events) == 2, f"Expected 2 events from 2 paginated files, got {len(events)}"

            # First event from page 1
            assert events[0]["username"] == "alice-admin"
            assert events[0]["event"] == "AttachUserPolicy"
            assert events[0]["risk_level"] == "CRITICAL"

            # Second event from page 2
            assert events[1]["username"] == "bob-dev"
            assert events[1]["event"] == "CreateAccessKey"
            assert events[1]["risk_level"] == "HIGH"

    def test_s3_pagination_handles_aws_client_error_gracefully(self):
        """
        TEST 4: Resilient Error Handling in S3 Pagination
        
        Plain Language:
        If AWS S3 returns an Access Denied error or is temporarily unreachable
        when attempting pagination, fetch_iam_events() should catch the error,
        log a clear error message, and return an empty list [] instead of crashing.
        """
        mock_s3 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied to S3 Bucket"}},
            "ListObjectsV2"
        )
        mock_s3.get_paginator.return_value = mock_paginator

        with patch("boto3.client", return_value=mock_s3):
            events = detector_core.fetch_iam_events("restricted-bucket")
            assert events == []
