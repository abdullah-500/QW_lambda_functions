import boto3
from boto3.dynamodb.conditions import Key

import json
import os 

def updateUserDeviceId(client_id, endpoints):

    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).update_item(
        Key={
            'client_id': client_id,
        },
        UpdateExpression="set gcm_endpoint = :g",
        ExpressionAttributeValues={
            ':g': endpoints
        },
        ReturnValues="UPDATED_NEW"
    )

    return

def getPlatformEndpointsByClientId(client_id):
    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
        KeyConditionExpression=Key('client_id').eq(client_id)
        )

    if response['Items']:
        if len(response['Items'])>0:
            return response['Items'][0]['gcm_endpoint']
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


def lambda_handler(event, context):
    print (event['body'])

    body = json.loads(event['body'])
    
    client_id = getClientIdByUserEmail(body['email'])

    currentPlatformEndpoint = getPlatformEndpointByDeviceId(body['deviceid'])
    if client_id and currentPlatformEndpoint:
        platformEndpoints = getPlatformEndpointsByClientId(client_id)
        if currentPlatformEndpoint in platformEndpoints:
            platformEndpoints.remove(currentPlatformEndpoint)
            updateUserDeviceId(client_id, platformEndpoints)

            body = {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "status": "Logged out"
                    }
                    ),
                        "headers": {
                            'Access-Control-Allow-Origin': '*'
                        }
                    }
        else:
            body = {
                "statusCode": 404,
                "body": json.dumps(
                    {
                        "status": "User or deviceId not found"
                    }
                    ),
                        "headers": {
                            'Access-Control-Allow-Origin': '*'
                        }
                    }


    else:
        body = {
            "statusCode": 404,
            "body": json.dumps(
                {
                    "status": "User or deviceId not found"
                }
                ),
                    "headers": {
                        'Access-Control-Allow-Origin': '*'
                    }
                }

    return body    

