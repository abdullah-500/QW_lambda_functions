import json, os, logging, time, sys 
import boto3
import email
import base64

from boto3.dynamodb.conditions import Key

sys.path.append('./lib')
import refreshToken as refresh
import parseToken

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def getQWEmailsByAddress(user_emails):
    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
        IndexName='user_emails_index',
        KeyConditionExpression=Key('user_emails').eq(user_emails)
        )

    if response['Items']:
        if len(response['Items'])>0:
            return response['Items'][0]['quickwordz_email']
        else:
            return False
    else:
        return False

def sendEmail(email_model, qw_user_email):

    client = boto3.client('ses')
    response = client.send_email(
        Destination={
            'CcAddresses': email_model['cc'],
            'ToAddresses': [email_model['address']],
        },
        Message={
            'Body': {
                'Text': {
                    'Charset': 'UTF-8',
                    'Data': email_model['body']
                },
            },
            'Subject': {
                'Charset': 'UTF-8',
                'Data': email_model['subject']
            },
        },
        ReplyToAddresses=[email_model['replyTo']],
        Source=qw_user_email
    )

    print(response)
    return

def lambda_handler(event, context):
    
    body = json.loads(event['body'])

    if 'cc' in body:
        cc = body['cc']
    else:
        cc = []


    email_model = {
        "address": body['address'],
        "cc": cc,
        "replyTo": body['replyTo'],
        "body": body['body'],
        "subject": body['subject']
    }

    if "RefreshToken" in event:
        RefreshToken = body['RefreshToken']
    else:
        RefreshToken = None

    user_emails = parseToken.getClaim(event['headers']['Authorization'], 'email')
    qw_user_email = getQWEmailsByAddress(user_emails)

    sendEmail(email_model, qw_user_email)

    if RefreshToken:
        response = refresh.refreshToken(RefreshToken, os.environ['ClientId'])
        body = json.loads(response['body'])
        response['body'] = json.dumps(body)
    else:
        response = {
            "statusCode": 200,
            "headers": {
                'Access-Control-Allow-Origin': '*'
            }
        }

    return response
    