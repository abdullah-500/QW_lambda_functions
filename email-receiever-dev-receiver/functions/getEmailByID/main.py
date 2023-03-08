import json, os, logging, sys
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

sys.path.append('./lib')
import refreshToken as refresh

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def getEmailByID(email_id):

    response = boto3.resource('dynamodb').Table(os.environ['emails_table_name']).get_item( Key = {'message_id': email_id} )

    return response['Item']

def lambda_handler(event, context):
    
    email_id = event['queryStringParameters']['emailID']

    if "RefreshToken" in event['queryStringParameters']:
        RefreshToken = event['queryStringParameters']['RefreshToken']
    else:
        RefreshToken = None
    
    
    email_info = getEmailByID(email_id)

    summary = {
        "id": email_info['message_id'],
        "attachments": int(email_info['attachments']),
        "senderPictureURL": email_info['senderPictureURL'],
        "from_email": email_info['from_email'],
        "from_username": email_info['from_username'],
        "summary": email_info['summary'],
        "date": email_info['date'],
        "subject": email_info['subject'],
        "original_email": email_info['original_email'],
        "small_summary": email_info['small_summary'],
        "large_summary": email_info['large_summary'],
        "to": email_info['to']
    }

    if RefreshToken:
        response = refresh.refreshToken(RefreshToken, os.environ['ClientId'])
        body = json.loads(response['body'])
        body["Email"] = summary
        response['body'] = json.dumps(body)
    else:
        body = { "Email": summary }
        response = {
            "statusCode": 200,
            "body": json.dumps(body),
            "headers": {
                'Access-Control-Allow-Origin': '*'
            }
        }

    return response