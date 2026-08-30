import os
from pathlib import Path
import pandas as pd
from dotenv import load_dotenv
from detector_core import fetch_iam_events

# Load environment variables from .env in project root
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# CloudTrail bucket name configured via environment variable with fallback
bucket_name = os.getenv('S3_BUCKET_NAME') or os.getenv('CLOUDTRAIL_BUCKET_NAME')
if not bucket_name or bucket_name == 'your-cloudtrail-bucket-name':
    print("WARNING: S3_BUCKET_NAME / CLOUDTRAIL_BUCKET_NAME is not set in .env. Using placeholder 'your-cloudtrail-bucket-name'.")
    bucket_name = 'your-cloudtrail-bucket-name'

iam_events = fetch_iam_events(bucket_name)

if not iam_events:
    print("No IAM events found in CloudTrail logs. Skipping anomaly analysis.")
    df = pd.DataFrame(columns=[
        'username', 'event', 'policy', 'risk_level', 'time',
        'source_ip', 'event_code', 'hour', 'user_event_count', 'anomaly_label'
    ])
    df.to_csv('iam_risk_report.csv', index=False)
    print("Saved empty report to iam_risk_report.csv")
else:
    df = pd.DataFrame(iam_events)

    event_map = {'CreateUser': 0, 'AttachUserPolicy': 1, 'CreateAccessKey': 2, 'PutUserPolicy': 3, 'AttachRolePolicy': 4, 'CreateRole': 5}
    df['event_code'] = df['event'].map(event_map)

    df['hour'] = pd.to_datetime(df['time']).dt.hour

    user_counts = df['username'].value_counts()
    df['user_event_count'] = df['username'].map(user_counts)

    mean_count = df['user_event_count'].mean()
    std_count = df['user_event_count'].std()


    def calculate_anomaly(row):
        if std_count == 0 or pd.isna(std_count):
            return 'Normal'
        z_score = abs(row['user_event_count'] - mean_count) / std_count
        if z_score > 1 or row['hour'] < 6 or row['hour'] > 22:
            return 'ANOMALY'
        return 'Normal'


    df['anomaly_label'] = df.apply(calculate_anomaly, axis=1)

    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    df['risk_rank'] = df['risk_level'].map(risk_order)
    df = df.sort_values('risk_rank').drop(columns='risk_rank')

    print(df)

    df.to_csv('iam_risk_report.csv', index=False)
    print("Saved to iam_risk_report.csv")