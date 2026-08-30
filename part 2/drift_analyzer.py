import boto3
import time
import csv
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

def get_attached_policies(username):
    try:
        response = iam.list_attached_user_policies(UserName=username)
        return response['AttachedPolicies']
    except (ClientError, BotoCoreError) as e:
        print(f"ERROR: Could not fetch policies for {username} - {e}")
        return []

def get_service_last_accessed(user_arn, max_wait=60):
    try:
        job = iam.generate_service_last_accessed_details(Arn=user_arn)
        job_id = job['JobId']
    except (ClientError, BotoCoreError) as e:
        print(f"ERROR: Could not start Access Advisor job for {user_arn} - {e}")
        return []

    waited = 0
    while waited < max_wait:
        try:
            result = iam.get_service_last_accessed_details(JobId=job_id)
        except (ClientError, BotoCoreError) as e:
            print(f"ERROR: Could not fetch job status - {e}")
            return []

        if result['JobStatus'] == 'COMPLETED':
            return result['ServicesLastAccessed']
        if result['JobStatus'] == 'FAILED':
            print(f"ERROR: Access Advisor job failed for {user_arn}")
            return []

        time.sleep(2)
        waited += 2

    print(f"WARNING: Access Advisor job timed out for {user_arn}")
    return []

def determine_risk(policy_name, is_used):
    if is_used:
        return 'OK'
    if policy_name == 'AdministratorAccess':
        return 'HIGH RISK - Unused Admin Permission'
    return 'MEDIUM RISK - Unused Permission'

def write_drift_report(all_rows, filename='unused_permissions_report.csv'):
    if not all_rows:
        print("WARNING: No data to write - skipping CSV export")
        return
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['username', 'policy', 'service', 'status', 'risk'])
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
        user_arn = user['Arn']
        print(f"\nUser: {username}")

        policies = get_attached_policies(username)
        if not policies:
            print("  No attached policies (or fetch failed)")
            policy_names = ['None']
        else:
            policy_names = [p['PolicyName'] for p in policies]
            for policy in policies:
                print(f"  Policy: {policy['PolicyName']}")

        print("  --- Service Usage ---")
        services = get_service_last_accessed(user_arn)
        if not services:
            print("  No service usage data available (skipping)")
            continue

        used_count = 0
        unused_count = 0

        for service in services:
            is_used = bool(service.get('LastAuthenticated'))
            status = 'USED' if is_used else 'NEVER USED'

            if is_used:
                used_count += 1
            else:
                unused_count += 1
                print(f"  NEVER USED: {service['ServiceName']}")

            for policy_name in policy_names:
                risk = determine_risk(policy_name, is_used)
                all_rows.append({
                    'username': username,
                    'policy': policy_name,
                    'service': service['ServiceName'],
                    'status': status,
                    'risk': risk
                })

        print(f"  Summary: {used_count} services used, {unused_count} never used")

    write_drift_report(all_rows)