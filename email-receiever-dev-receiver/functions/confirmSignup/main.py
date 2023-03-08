import boto3
import json
import os 


def lambda_handler(event, context):

    client = boto3.client("cognito-idp")

    print(event)

    try: 
        response = client.confirm_sign_up(
            ClientId=os.environ['ClientId'],
            Username=event['queryStringParameters']['email'],
            ConfirmationCode=event['queryStringParameters']['confirmationCode'],
        )
        print (response)
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "status": '%s email has been successfully verified' % (event['queryStringParameters']['email'])
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