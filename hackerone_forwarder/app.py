import boto3
import json
import datetime
import os

securityhub = boto3.client('securityhub')

def getSeverityScore(rating):
    if rating == 'CRITICAL':
        return "10"
    elif rating == 'HIGH':
        return "7"
    elif rating == 'MEDIUM':        
        return "5"
    else:
        return "1"

def lambda_handler(event, context):
    all_findings = []
    finding_account_id = context.invoked_function_arn.split(":")[4]
    finding_account_region = os.environ['AWS_REGION']
    uid = event['data']['report']['id']
    fid = finding_account_region + "/" + finding_account_id + "/" + uid
    updatedAt = datetime.datetime.utcnow().isoformat("T") + "Z"
    reportAttributes = event['data']['report']['attributes']
    reporter = event['data']['report']['relationships']['reporter']['data']['attributes']['username']
    severityRating = event['data']['report']['relationships']['severity']['data']['attributes']['rating'].upper()
    severityScore = getSeverityScore(severityRating)
    createdAt = event['data']['activity']['attributes']['created_at']
    reportUrl = "https://hackerone.com/reports/" + uid

    finding = {
        "SchemaVersion": "2018-10-08",
        "RecordState": "ACTIVE",
        "ProductArn": "arn:aws:securityhub:" + finding_account_region + "::product/hackerone/vulnerability-intelligence",
        "ProductFields": {
            "ProviderName": "HackerOne"  
        },
        "Description": "Once logged in to HackerOne, see more at " + reportUrl,
        "GeneratorId": reporter,
        "AwsAccountId": finding_account_id,
        "Id": fid,
        "Types": [
            "Software and Configuration Checks/Vulnerabilities/CVE"
        ],
        "CreatedAt": createdAt,
        "UpdatedAt": updatedAt,
        "FirstObservedAt": createdAt,
        "Resources": [{
            "Type": "AwsAccount",
            "Id": "AWS::::Account:" + finding_account_id
        }],
        "Severity": {
            "Label": severityRating,
            "Original": severityScore
        },
        "Title": reportAttributes['title']
    }

    all_findings.append(finding)

    securityhub_cli = boto3.client('securityhub', region_name=finding_account_region)

    securityhub_cli.batch_import_findings(
        Findings=all_findings
    )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Finding in " + finding_account_region + " " + finding_account_id + " added to Security Hub."
        }),
    }