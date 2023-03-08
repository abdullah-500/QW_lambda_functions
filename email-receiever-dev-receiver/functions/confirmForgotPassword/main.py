import boto3
import json
import os 

def lambda_handler(event, context):
    print (event['body'])
    body = json.loads(event['body'])
    client = boto3.client("cognito-idp")

    try:
        response = client.confirm_forgot_password(
            ClientId=os.environ['ClientId'],
            Username=body['email'],
            Password=body['password'],
            ConfirmationCode=body['confirmationCode']
        )

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "status": "Success"
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
        client.exceptions.InternalErrorException
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
    except client.exceptions.UserNotConfirmedException:
        return {
            "statusCode": 400,
            "body": json.dumps(
                {
                    "status": "User hasn't been confirmed yet"
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
            "statusCode": 400,
            "body": json.dumps(
                {
                    "status": "User not found"
                }
                ),
                    "headers": {
                        'Access-Control-Allow-Origin': '*'
                    }
            }