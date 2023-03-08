import json, os, logging, time, sys 
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

sys.path.append('./lib')
import refreshToken as refresh

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    body = json.loads(event['body'])
    message_id = body['email_id']

    client = boto3.client('dynamodb')

    try:
        delete_results = client.delete_item(
        TableName=os.environ['emails_table_name'],
        Key={
            'message_id':
            {"S": message_id}
        },
        ReturnValues="ALL_OLD")

        if "Attributes" not in delete_results:
            status = "Email not found"
            statusCode = 400
        else:
            status = "Email successfully deleted"
            statusCode = 200

    except (client.exceptions.ConditionalCheckFailedException,
            client.exceptions.ProvisionedThroughputExceededException,
            client.exceptions.ItemCollectionSizeLimitExceededException,
            client.exceptions.TransactionConflictException,
            client.exceptions.RequestLimitExceeded,
            client.exceptions.InternalServerError) as e:
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
    except client.exceptions.ResourceNotFoundException as e:
        return {
            "statusCode": 400,
            "body": json.dumps(
                {
                    "status": "Email not found"
                }
                ),
                    "headers": {
                        'Access-Control-Allow-Origin': '*'
                    }
            }


    if "RefreshToken" in body:
        RefreshToken = body['RefreshToken']
    else:
        RefreshToken = None


    if RefreshToken:
        response = refresh.refreshToken(RefreshToken, os.environ['ClientId'])
        body = json.loads(response['body'])
        body["status"] = status
        response['body'] = json.dumps(body)
        response['statusCode'] = statusCode
    else:
        response = {
            "statusCode": statusCode,
            "body": json.dumps({"status": status}),
            "headers": {
                'Access-Control-Allow-Origin': '*'
            }
        }

    return response
    