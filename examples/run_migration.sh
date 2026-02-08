#!/bin/bash

# Extract rules
sudo python3 extract_firewall_rules.py

# Upload to S3 (optional)
aws s3 cp firewall_rules.json s3://AWS-S3-BUCKET-NAME/firewall-rules.json

# Trigger Step Function
aws stepfunctions start-execution \
    --state-machine-arn arn:aws:states:ap-south-1:AWS-ACCOUNT-ID:stateMachine:on-prem-firewall-migration \
    --name "fw-migration-$(date +%Y%m%d-%H%M%S)" \
    --input file://firewall_rules.json
