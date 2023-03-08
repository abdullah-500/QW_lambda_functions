import boto3
from boto3.dynamodb.conditions import Key

import json
import os
import sys

sys.path.append('./lib')
import refreshToken as refresh


def updateUserDeviceId(client_id, device_id, endpoint, action):

    if action == "update":
        UpdateExpression="set device_id = :d, gcm_endpoint = list_append(gcm_endpoint, :g)"
    else:
        UpdateExpression="set device_id = :d, gcm_endpoint = :g"

    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).update_item(
    Key={
        'client_id': client_id,
    },
    UpdateExpression=UpdateExpression,
    ExpressionAttributeValues={
        ':d': device_id,
        ':g': [endpoint]
    },
    ReturnValues="UPDATED_NEW"
)

    response = boto3.resource('dynamodb').Table(os.environ['devices_table_name']).put_item(Item=
        {
            "device_id": device_id,
            "gcm_endpoint": endpoint
        }
    )

    return

def getClientIdByUserEmail(user_emails):
    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
        IndexName='user_emails_index',
        KeyConditionExpression=Key('user_emails').eq(user_emails)
        )
    if response['Items']:
        if len(response['Items'])>0:
            return response['Items'][0]['client_id']
        else:
            return False
    else:
        return False

def getPlatformEndpointByDeviceId(device_id):
    response = boto3.resource('dynamodb').Table(os.environ['devices_table_name']).query(
        KeyConditionExpression=Key('device_id').eq(device_id)
        )

    print ("###")
    print (response)
    print ("###")

    if response['Items']:
        if len(response['Items'])>0:
            return response['Items'][0]['gcm_endpoint']
        else:
            return False
    else:
        return False


def getPlatformEndpointsByClientId(client_id):
    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
        KeyConditionExpression=Key('client_id').eq(client_id)
        )

    if response['Items']:
        if len(response['Items'])>0:
            if "gcm_endpoint" in response['Items'][0]:
                return response['Items'][0]['gcm_endpoint']
            else:
                return False
        else:
            return False
    else:
        return False

def createPlatformEndpoint(device_id, email):
    client = boto3.client('sns')
    try:
        response = client.create_platform_endpoint(
            PlatformApplicationArn=os.environ['PlatformApplicationArn'],
            Token=device_id,
            CustomUserData=json.dumps({"email": email})
        )
    except client.exceptions.InvalidParameterException as e:
        print (e)

    return (response['EndpointArn'])

def lambda_handler(event, context):
    print (event['body'])
    body = json.loads(event['body'])

    dynamodb = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name'])

    client_id = getClientIdByUserEmail(body['email'])
    if client_id:
        device_id = body['deviceid']

        endpoint = getPlatformEndpointByDeviceId(device_id)
        print (endpoint)
        all_endpoints = getPlatformEndpointsByClientId(client_id)
        print (all_endpoints)
        if all_endpoints:
            action = "update"
        else:
            action = "create"
        
        if not endpoint:
            endpoint = createPlatformEndpoint(device_id, body['email'])
            updateUserDeviceId(client_id, device_id, endpoint, action)
        else:
            if endpoint not in str(all_endpoints):
               updateUserDeviceId(client_id, device_id, endpoint, action) 

        if 'RefreshToken' in body:
            body = refresh.refreshToken(body['RefreshToken'], os.environ['ClientId'])
        else:
            body = {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "status": "DeviceID successfully set"
                }
                ),
                    "headers": {
                        'Access-Control-Allow-Origin': '*'
                    }
            }
    else:
        body = {
            "statusCode": 401,
            "body": json.dumps(
                {
                    "status": "User not found"
                }
                ),
                    "headers": {
                        'Access-Control-Allow-Origin': '*'
                    }
            }

    return body