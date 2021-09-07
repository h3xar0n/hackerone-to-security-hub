import boto3
import json
import uuid
import datetime

securityhub = boto3.client('securityhub')

def lambda_handler(event, context):
    all_findings = []
    uid = event['data']['activity']['id']
    fid = "us-east-1/021740258839/" + str(uid)
    time = datetime.datetime.utcnow().isoformat("T") + "Z"
    data = event['data']
    reportAttributes = event['data']['report']['attributes']
    severityRating = event['data']['report']['relationships']['severity']['data']['attributes']['rating'].upper()
    # severityScore = str(event['data']['report']['relationships']['severity']['data']['attributes']['score'])

    finding = {
        "SchemaVersion": "2018-10-08",
        "RecordState": "ACTIVE",
        # "ProductArn": "arn:aws:securityhub:us-east-1:021740258839:product/hackerone/vulnerability-intelligence",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/hackerone/vulnerability-intelligence",
        # "ProductArn": "arn:aws:securityhub:us-east-1:021740258839:product/021740258839/default",
        "ProductFields": {
            "ProviderName": "HackerOne"  
        },
        "Description": reportAttributes['title'],
        "GeneratorId": "acme-vuln-9ab348",
        "AwsAccountId": "021740258839",
        "Id": fid,
        "Types": [
            "Software and Configuration Checks/Vulnerabilities/CVE"
        ],
        "CreatedAt": time,
        "UpdatedAt": time,
        "FirstObservedAt": time,
        "Resources": [{
            "Type": "AwsAccount",
            "Id": "AWS::::Account:021740258839"
        }],
        "Severity": {
            "Label": severityRating,
            "Original": "5"
        },
        "Title": "HackerOne: " + reportAttributes['title']
    }

    all_findings.append(finding)

    securityhub_cli = boto3.client('securityhub', region_name="us-east-1")

    securityhub_cli.batch_import_findings(
        Findings=all_findings
    )