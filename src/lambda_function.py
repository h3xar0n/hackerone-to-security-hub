import boto3
import json
import uuid
import datetime
from utils import retry
import logging

securityhub = boto3.client('securityhub')

def get_product_arn(securityhub_region):
    return "arn:aws:securityhub:%s::product/hackerone/vulnerability-intelligence" % (securityhub_region)

def get_lambda_account_id(context):
    lambda_account_id = context.invoked_function_arn.split(":")[4]
    return lambda_account_id

def lambda_handler(event, context):
    lambda_account_id = get_lambda_account_id(context)
    lambda_region = os.getenv("AWS_REGION")
    logger.info("Invoking lambda_handler in Region %s AccountId %s" % (lambda_region, lambda_account_id))
    finding_account_id = os.getenv("AWS_ACCOUNT_ID", lambda_account_id)
    securityhub_region = os.getenv("REGION", lambda_region)
    product_arn = get_product_arn(securityhub_region)
    
    all_findings = []
    uid = event['data']['activity']['id']
    fid = str(securityhub_region) + "/" + str(finding_account_id) + "/" + str(uid)
    time = datetime.datetime.utcnow().isoformat("T") + "Z"
    data = event['data']
    reportAttributes = event['data']['report']['attributes']
    severityRating = event['data']['report']['relationships']['severity']['data']['attributes']['rating'].upper()
    # severityScore = str(event['data']['report']['relationships']['severity']['data']['attributes']['score'])

    finding = {
        "SchemaVersion": "2018-10-08",
        "RecordState": "ACTIVE",
        "ProductArn": product_arn,
        "ProductFields": {
            "ProviderName": "HackerOne"  
        },
        "Description": reportAttributes['title'],
        "GeneratorId": "acme-vuln-9ab348",
        "AwsAccountId": str(finding_account_id),
        "Id": fid,
        "Types": [
            "Software and Configuration Checks/Vulnerabilities/CVE"
        ],
        "CreatedAt": time,
        "UpdatedAt": time,
        "FirstObservedAt": time,
        "Resources": [{
            "Type": "AwsAccount",
            "Id": "AWS::::Account:" + str(finding_account_id)
        }],
        "Severity": {
            "Label": severityRating,
            "Original": "5"
        },
        "Title": reportAttributes['title']
    }

    all_findings.append(finding)

    securityhub_cli = boto3.client('securityhub', region_name="us-east-1")

    securityhub_cli.batch_import_findings(
        Findings=all_findings
    )

def get_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    return logger

logger = get_logger()
