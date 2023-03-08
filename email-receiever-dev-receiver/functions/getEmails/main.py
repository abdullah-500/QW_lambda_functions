import json, os, logging, time, sys 
import boto3
import datetime
import base64
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
import email

sys.path.append('./lib')
import refreshToken as refresh
import parseToken

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def base64pageEncode(page):
    message_bytes = page.encode('ascii')
    base64_bytes=base64.b64encode(message_bytes)
    encodedPage = base64_bytes.decode('ascii')
    return encodedPage

def base64pageDecode(page):

    base64_bytes = page.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    decodedPage = message_bytes.decode('ascii')

    return decodedPage

def getEmailsByAddress(source_email, page=None):
    if page:
        response = boto3.resource('dynamodb').Table(os.environ['emails_table_name']).query(
            IndexName='emails_index',
            KeyConditionExpression=Key('to').eq(source_email),
            ExclusiveStartKey=page,
            Limit=10,
            ScanIndexForward=False
            )
    else:
        response = boto3.resource('dynamodb').Table(os.environ['emails_table_name']).query(
            IndexName='emails_index',
            KeyConditionExpression=Key('to').eq(source_email),
            Limit=10,
            ScanIndexForward=False
            )

    # print (response)
    message_ids = []

    if response['Items']:
        for item in response['Items']:
            message_ids.append(item['message_id'])

    if "LastEvaluatedKey" in response:
        encodedPage = base64pageEncode("%s:%s" % (response['LastEvaluatedKey']['message_id'], response['LastEvaluatedKey']['timestamp']))
        return [message_ids, encodedPage]
    else:
        return [message_ids, None]

def dynamoDB_connector(tablename, data):
    dynamodb = boto3.resource('dynamodb').Table(tablename)
    dynamodb.put_item(Item=data)
    return

def lambda_handler(event, context):
    
    source = parseToken.getClaim(event['headers']['Authorization'], 'email')

    print (source)
    page = event['queryStringParameters']['LastEvaluatedKey']
    if "RefreshToken" in event['queryStringParameters']:
        RefreshToken = event['queryStringParameters']['RefreshToken']
    else:
        RefreshToken = None
    
    if page != "0":
        decodedPage=base64pageDecode(page)
        decodedPageArray=decodedPage.split(":")
        message_ids, next_page = getEmailsByAddress(source, {"to": source, "message_id": decodedPageArray[0], "timestamp": decodedPageArray[1]})
    else:
        message_ids, next_page = getEmailsByAddress(source)

    summary = []

    for messageId in message_ids:
        response = boto3.resource('dynamodb').Table(os.environ['emails_table_name']).get_item( Key = {'message_id': messageId} )
        summary.append({
            "id": response['Item']['message_id'],
            "attachments": int(response['Item']['attachments']),
            "senderPictureURL": response['Item']['senderPictureURL'],
            "from_email": response['Item']['from_email'],
            "from_username": response['Item']['from_username'],
            "summary": response['Item']['summary'],
            "date": response['Item']['date'],
            "subject": response['Item']['subject'],
            "original_email": response['Item']['original_email'],
            "small_summary": response['Item']['small_summary'],
            "large_summary": response['Item']['large_summary'],
            "to": response['Item']['to'],
            "timestamp": response['Item']['timestamp'],
            })


    print (summary)
    summary = sorted(summary, key=lambda k: k['timestamp'], reverse=True) 
    
    for item in summary:
        del item['timestamp']

    if RefreshToken:
        response = refresh.refreshToken(RefreshToken, os.environ['ClientId'])
        body = json.loads(response['body'])
        body["Emails"] = summary
        if next_page:
            body['LastEvaluatedKey']=str(next_page)
        response['body'] = json.dumps(body)
    else:
        if next_page:
            body = {
                "emails": summary,
                "LastEvaluatedKey": str(next_page)
                }
        else:
            body = { "emails": summary }
        response = {
            "statusCode": 200,
            "body": json.dumps(body),
            "headers": {
                'Access-Control-Allow-Origin': '*'
            }
        }

    return response