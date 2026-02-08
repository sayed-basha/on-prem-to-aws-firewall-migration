# On prem Firewall to AWS Security Group Migration

An automated solution for migrating on-premises firewalld rules to AWS Security Groups using Lambda and Step Functions.

##  Overview

This project automates the migration of firewall rules from on-premises servers to AWS Security Groups, preserving source IP restrictions and rule configurations.

### Key Features

-  Extracts firewalld rules (services, ports, rich rules)
-  Preserves source IP whitelisting (single host `/32` and subnet rules)
-  Automated deployment using AWS Step Functions
-  Custom VPC support
-  Rule validation and verification
-  Comprehensive error handling and logging

##  Architecture

┌─────────────────────┐
│      Server         │
│   (On-Premises)     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Extract Firewall    │
│ Rules Script        │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ firewall_rules.json │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ AWS Step Functions  │
└──────────┬──────────┘
           │
           ├──────────────────────┐
           ▼                      ▼
┌──────────────────┐   ┌──────────────────┐
│ Lambda: Create   │   │ Lambda: Validate │
│ Security Group   │   │ Migration        │
└──────────────────┘   └──────────────────┘
           │
           ▼
┌─────────────────────┐
│ AWS Security Group  │
│ (with rules)        │
└─────────────────────┘
```

##  Prerequisites

- Fedora/RHEL server with `firewalld`
- AWS Account with appropriate permissions
- Python 3.8+
- AWS CLI configured
- IAM permissions for Lambda, Step Functions, EC2, VPC

##  Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/sayed-basha/on-prem-to-aws-firewall-migration.git
cd on-prem-to-aws-firewall-migration
```

### 2. Extract Firewall Rules from Fedora
```bash
sudo python3 scripts/extract_firewall_rules.py
```

### 3. Deploy Lambda Functions

Deploy the Lambda functions from the `lambda/` directory to AWS.

### 4. Create Step Functions State Machine

Use the definition in `step-functions/state-machine-definition.json`

### 5. Execute Migration
```bash
aws stepfunctions start-execution \
    --state-machine-arn arn:aws:states:REGION:ACCOUNT:stateMachine:on-prem-firewall-migration \
    --input file://firewall_rules.json
```

##  Configuration

### Extract Script Configuration

Edit `scripts/extract_firewall_rules.py`:
```python
OUTPUT_DIR = '/path/to/output'  # Set your output directory
```

### Lambda Configuration

Edit `lambda/create_security_group.py`:
```python
CUSTOM_VPC_ID = 'vpc-xxxxx'  # Set your VPC ID
```

##  Example Output

### On prem Firewall Rules
```bash
services: ssh http https
ports: 8080/tcp
rich rules: 
  rule family="ipv4" source address="10.10.0.0/32" port port="22" protocol="tcp" accept
```

### AWS Security Group Rules
```json
{
  "IpProtocol": "tcp",
  "FromPort": 22,
  "ToPort": 22,
  "IpRanges": [{
    "CidrIp": "10.10.0.0/32",
    "Description": "Rich rule: tcp/22 from 10.10.0.0/32"
  }]
}
```

##  Security Considerations

- Source IP restrictions are preserved during migration
- `/32` CIDR notation for single-host whitelisting
- VPC isolation
- IAM least-privilege access
- CloudWatch logging enabled

##  Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

**SayedBasha**
- LinkedIn: https://linkedin.com/in/sayedbasha
- GitHub:

##  Acknowledgments

- Built as a learning project to understand enterprise cloud migration patterns
- Inspired by real-world firewall migration scenarios

** If you find this project helpful, please give it a star!**