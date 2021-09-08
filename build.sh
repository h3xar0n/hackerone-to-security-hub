#!/bin/bash
echo "Enter the name of an S3 bucket you own to host the configuration:"
read S3BUCKET
aws cloudformation package --template-file template.yaml --output-template-file packaged-template.yaml --s3-bucket $S3BUCKET
echo "Template file packaged in $S3BUCKET. Enter a name for your stack:"
read STACKNAME
aws cloudformation deploy --template-file packaged-template.yaml --stack-name $STACKNAME --capabilities CAPABILITY_IAM
echo "Target the HackerOne Webhook at the following URL:"
aws cloudformation describe-stacks --stack-name $STACKNAME --query "Stacks[0].Outputs[?OutputKey=='HackerOneForwarderUrl'].OutputValue" --output text