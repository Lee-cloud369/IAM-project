import boto3
import gzip
import json
from botocore.exceptions import ClientError, BotoCoreError


def get_risk_level(event_name, policy_name):
    if event_name == 'AttachUserPolicy' and policy_name == 'AdministratorAccess':
        return 'CRITICAL'
    elif event_name in ['AttachUserPolicy', 'AttachRolePolicy']:
        return 'HIGH'
    elif event_name == 'CreateAccessKey':
        return 'HIGH'
    elif event_name in ['CreateUser', 'CreateRole']:
        return 'MEDIUM'
    else:
        return 'LOW'


def extract_username(user_identity):
    username = user_identity.get('userName')
    if not username:
        if user_identity.get('type') == 'Root':
            username = 'root (console login)'
        else:
            username = user_identity.get('arn', 'unknown').split('/')[-1]
    return username


def extract_policy_name(request_params):
    policy_name = request_params.get('policyArn', 'N/A')
    if policy_name != 'N/A':
        policy_name = policy_name.split('/')[-1]
    return policy_name


def fetch_iam_events(bucket_name):
    s3 = boto3.client('s3')

    all_files = []
    try:
        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name, Prefix='AWSLogs/'):
            all_files.extend(page.get('Contents', []))
    except (ClientError, BotoCoreError) as e:
        print(f"ERROR: Could not list objects in bucket {bucket_name} - {e}")
        return []

    iam_events = []
    relevant_events = ['AttachUserPolicy', 'CreateAccessKey', 'CreateUser', 'PutUserPolicy', 'AttachRolePolicy', 'CreateRole']

    for file in all_files:
        file_key = file['Key']

        try:
            obj_data = s3.get_object(Bucket=bucket_name, Key=file_key)
            with gzip.GzipFile(fileobj=obj_data['Body']) as f:
                log_content = json.loads(f.read())
        except (ClientError, BotoCoreError) as e:
            print(f"WARNING: Could not fetch {file_key} - {e}")
            continue
        except (OSError, json.JSONDecodeError) as e:
            print(f"WARNING: Could not read/parse {file_key} - {e}")
            continue

        for event in log_content.get('Records', []):
            event_name = event.get('eventName', '')

            if event_name in relevant_events:
                user_identity = event.get('userIdentity', {})
                username = extract_username(user_identity)

                request_params = event.get('requestParameters', {}) or {}
                policy_name = extract_policy_name(request_params)

                iam_events.append({
                    'username': username,
                    'event': event_name,
                    'policy': policy_name,
                    'risk_level': get_risk_level(event_name, policy_name),
                    'time': event.get('eventTime', ''),
                    'source_ip': event.get('sourceIPAddress', ''),
                })

    return iam_events