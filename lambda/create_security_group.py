import boto3
import json
from datetime import datetime

ec2 = boto3.client('ec2')


CUSTOM_VPC_ID = 'vpc-xxxxxxx'  # REPLACE THIS with your actual VPC ID


def lambda_handler(event, context):
    """Create AWS Security Group from firewall rules"""
    
    print("=" * 50)
    print("FULL EVENT RECEIVED:")
    print(json.dumps(event, indent=2))
    print("=" * 50)
    
    # Handle different input formats
    rules = None
    
    if 'rules' in event:
        print("Found 'rules' key in event")
        if isinstance(event['rules'], dict) and 'security_group_rules' in event['rules']:
            rules = event['rules']['security_group_rules']
        else:
            rules = event['rules']
    elif 'security_group_rules' in event:
        print("Found 'security_group_rules' key in event")
        rules = event['security_group_rules']
    else:
        print(f"ERROR: Cannot find rules. Event keys: {list(event.keys())}")
        return {
            'statusCode': 400,
            'error': f'Cannot find rules in event. Keys: {list(event.keys())}',
            'eventDebug': event
        }
    
    print(f"Extracted rules (type: {type(rules)}):")
    print(json.dumps(rules, indent=2))
    print(f"Number of rules: {len(rules) if rules else 0}")
    
    try:
        # Use custom VPC ID
        vpc_id = CUSTOM_VPC_ID
        print(f"Using custom VPC: {vpc_id}")
        
        # Verify VPC exists
        try:
            vpc_response = ec2.describe_vpcs(VpcIds=[vpc_id])
            if not vpc_response['Vpcs']:
                return {
                    'statusCode': 400,
                    'error': f'VPC {vpc_id} not found'
                }
            print(f" VPC verified: {vpc_id}")
        except Exception as vpc_error:
            return {
                'statusCode': 400,
                'error': f'Cannot access VPC {vpc_id}: {str(vpc_error)}'
            }
        
        # Create unique security group name
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        sg_name = f'firewalld-migrated-sg-{timestamp}'
        
        # Create Security Group
        print(f"Creating security group: {sg_name}")
        response = ec2.create_security_group(
            GroupName=sg_name,
            Description='Security group migrated from Firewalld firewall',
            VpcId=vpc_id
        )
        
        sg_id = response['GroupId']
        print(f" Created Security Group: {sg_id}")
        
        # Add tags for better identification
        ec2.create_tags(
            Resources=[sg_id],
            Tags=[
                {'Key': 'Name', 'Value': 'Firewalld-Migrated-SG'},
                {'Key': 'Source', 'Value': 'Firewalld-Firewall'},
                {'Key': 'MigrationDate', 'Value': timestamp}
            ]
        )
        print("Tags added")
        
        # Add ingress rules
        if rules and len(rules) > 0:
            print(f"Attempting to add {len(rules)} rules...")
            print("Rules to add:")
            print(json.dumps(rules, indent=2))
            
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=rules
                )
                print(f" Successfully added {len(rules)} ingress rules")
            except Exception as rule_error:
                print(f"Error adding rules: {str(rule_error)}")
                # Return error but keep the security group
                return {
                    'statusCode': 200,
                    'securityGroupId': sg_id,
                    'securityGroupName': sg_name,
                    'vpcId': vpc_id,
                    'rulesAdded': 0,
                    'ruleError': str(rule_error),
                    'message': f'Security group created but rules failed: {str(rule_error)}'
                }
        else:
            print("No rules to add!")
        
        return {
            'statusCode': 200,
            'securityGroupId': sg_id,
            'securityGroupName': sg_name,
            'vpcId': vpc_id,
            'rulesAdded': len(rules) if rules else 0,
            'message': 'Security group created successfully'
        }
    
    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'error': str(e),
            'traceback': traceback.format_exc()
        }