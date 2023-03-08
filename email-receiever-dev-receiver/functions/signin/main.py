import boto3
from boto3.dynamodb.conditions import Key

import json
import os 

def getUsernameByUserEmail(user_emails):
    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
        IndexName='user_emails_index',
        KeyConditionExpression=Key('user_emails').eq(user_emails)
        )
    print (response)
    if response['Items']:
        if len(response['Items'])>0:
            return response['Items'][0]['username']
        else:
            return False
    else:
        return False


def lambda_handler(event, context):
    print (event['body'])
    body = json.loads(event['body'])
    client = boto3.client("cognito-idp")

    try:
        response = client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': body['email'],
                'PASSWORD': body['password']
            },
            ClientId=os.environ['ClientId']
        )

        username = getUsernameByUserEmail(body['email'])

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "IdToken": response['AuthenticationResult']['IdToken'],
                    "AccessToken": response['AuthenticationResult']['AccessToken'],
                    "RefreshToken": response['AuthenticationResult']['RefreshToken'],
                    "username": username
                }
                ),
            "headers": {
                'Access-Control-Allow-Origin': '*'
            }
        }
    except (
        client.exceptions.ResourceNotFoundException,
        client.exceptions.InvalidParameterException,
        client.exceptions.TooManyFailedAttemptsException,
        client.exceptions.UnexpectedLambdaException,
        client.exceptions.UserLambdaValidationException,
        client.exceptions.NotAuthorizedException,
        client.exceptions.InvalidLambdaResponseException,
        client.exceptions.AliasExistsException,
        client.exceptions.TooManyRequestsException,
        client.exceptions.LimitExceededException,
        client.exceptions.InternalErrorException,
        client.exceptions.UserNotConfirmedException
    ) as e:
        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "status": str(e)
                }
                ),
                    "headers": {
                        'Access-Control-Allow-Origin': '*'
                    }
            }
    except client.exceptions.CodeMismatchException:
        return {
            "statusCode": 400,
            "body": json.dumps(
                {
                    "status": "Code mismatch error"
                }
                ),
                    "headers": {
                        'Access-Control-Allow-Origin': '*'
                    }
            }
    except client.exceptions.ExpiredCodeException:
        return {
            "statusCode": 400,
            "body": json.dumps(
                {
                    "status": "Code has expired"
                }        
                ),
                    "headers": {
                        'Access-Control-Allow-Origin': '*'
                    }
            }

    except client.exceptions.UserNotFoundException:
        return {
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