import boto3
import json
import os 
import sys 

sys.path.append('./lib')
import refreshToken as refresh

def lambda_handler(event, context):
    print (event['body'])
    body = json.loads(event['body'])
    refreshToken = refresh.refreshToken(body['RefreshToken'], os.environ['ClientId'])
    return refreshToken