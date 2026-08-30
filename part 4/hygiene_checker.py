import boto3
import time
import csv
import io
from datetime import datetime, timezone
from botocore.exceptions import ClientError, BotoCoreError

iam = boto3.client('iam')

def get_all_users():
    try:
        paginator = iam.get_paginator('list_users')
        users = []
        for page in paginator.paginate():
            users.extend(page.get('Users', []))
        return users
    except (ClientError, BotoCoreError) as e:
        print(f"ERROR: Could not list users - {e}")
        return []

def check_mfa(username):
    try:
        response = iam.list_mfa_devices(UserName=username)
        return len(response['MFADevices']) > 0
    except (ClientError, BotoCoreError) as e:
        print(f"ERROR: Could not check MFA for {username} - {e}")
        return None

def get_access_key_ages(username):
    try:
        response = iam.list_access_keys(UserName=username)
        key_ages = []
        for key in response['AccessKeyMetadata']:
            create_date = key['CreateDate']
            age_days = (datetime.now(timezone.utc) - create_date).days
            key_ages.append({
                'key_id': key['AccessKeyId'],
                'status': key['Status'],
                'age_days': age_days
            })
        return key_ages
    except (ClientError, BotoCoreError) as e:
        print(f"ERROR: Could not fetch access keys for {username} - {e}")
        return []

def get_root_last_used(max_attempts=15, delay_seconds=2):
    try:
        iam.generate_credential_report()
    except (ClientError, BotoCoreError) as e:
        print(f"ERROR: Could not initiate credential report generation - {e}")
        return None

    for _ in range(max_attempts):
        try:
            response = iam.get_credential_report()
            report_csv = response['Content'].decode('utf-8')

            reader = csv.DictReader(io.StringIO(report_csv))
            for row in reader:
                if row['user'] == '<root_account>':
                    return row['password_last_used']
            return 'Not found'
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['ReportInProgress', 'ReportInProgressException', 'ReportNotPresent', 'ReportNotPresentException']:
                time.sleep(delay_seconds)
                continue
            print(f"ERROR: Could not fetch credential report - {e}")
            return None
        except BotoCoreError as e:
            print(f"ERROR: Could not fetch credential report - {e}")
            return None

    print(f"WARNING: Credential report generation timed out after {max_attempts * delay_seconds}s")
    return None

def determine_mfa_risk(mfa_enabled):
    if mfa_enabled:
        return 'OK'
    return 'HIGH RISK - No MFA'

def determine_key_risk(age_days):
    if age_days >= 90:
        return 'MEDIUM RISK - Key not rotated (90+ days)'
    return 'OK'

def write_hygiene_report(all_rows, filename='hygiene_report.csv'):
    if not all_rows:
        print("WARNING: No data to write - skipping CSV export")
        return
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['username', 'check_type', 'detail', 'risk'])
            writer.writeheader()
            writer.writerows(all_rows)
        print(f"\nReport saved to {filename}")
    except IOError as e:
        print(f"ERROR: Could not write CSV file - {e}")

if __name__ == '__main__':
    users = get_all_users()
    all_rows = []

    for user in users:
        username = user['UserName']
        print(f"\nUser: {username}")

        mfa_enabled = check_mfa(username)
        if mfa_enabled is None:
            print("  MFA status: could not check")
        else:
            status = 'ENABLED' if mfa_enabled else 'NOT ENABLED'
            print(f"  MFA: {status}")
            all_rows.append({
                'username': username,
                'check_type': 'MFA',
                'detail': status,
                'risk': determine_mfa_risk(mfa_enabled)
            })

        keys = get_access_key_ages(username)
        if not keys:
            print("  No access keys")
        else:
            for key in keys:
                flag = " (ROTATE - 90+ days old)" if key['age_days'] >= 90 else ""
                print(f"  Access Key {key['key_id']} - {key['status']} - {key['age_days']} days old{flag}")
                all_rows.append({
                    'username': username,
                    'check_type': 'Access Key Age',
                    'detail': f"{key['key_id']} - {key['age_days']} days old",
                    'risk': determine_key_risk(key['age_days'])
                })

    print("\n--- Root Account ---")
    root_last_used = get_root_last_used()
    print(f"  Root password last used: {root_last_used}")
    all_rows.append({
        'username': '<root_account>',
        'check_type': 'Root Usage',
        'detail': f"Last used: {root_last_used}",
        'risk': 'INFO - review manually'
    })

    write_hygiene_report(all_rows)