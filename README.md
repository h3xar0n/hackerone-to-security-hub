# HackerOne to Security Hub Serverless App

Prerequisites:
1. AWS Security Hub is enabled in the region where you want to receive findings
1. Ensure you have the AWS CLI configured to deploy a serverless application to the same region where AWS Security Hub is enabled. If not, use the following steps:
    1. Install [the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)
    1. Retrieve the AWS Access Key ID and the AWS Secret Access Key for an identity that has permission to create an API Gateway, Lambda, and a new IAM Role for the Lambda to connect to Security Hub
    1. Use `aws configure` to set the credentials and the region where you have Security Hub enabled 
1. Create or select an S3 bucket to host the configuration.

Setup

1. `chmod 700 ./build.sh`
1. `./build.sh`
1. Aim your HackerOne Webhook at the URL that appears at the end.