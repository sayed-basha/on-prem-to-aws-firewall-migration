import boto3

ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    sg_id = event['securityGroupId']
    
    try:
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        rules = response['SecurityGroups'][0]['IpPermissions']
        
        return {
            'statusCode': 200,
            'validated': True,
            'rulesCount': len(rules)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'validated': False,
            'error': str(e)
        }