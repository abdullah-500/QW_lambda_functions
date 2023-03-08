import boto3
import botocore
import json
import os 

from boto3.dynamodb.conditions import Key

def signUp(email, password):

    try:
        client = boto3.client("cognito-idp")
        response = client.sign_up(
            ClientId=os.environ['ClientId'],
            Username=email,
            Password=password
        )
    except (client.exceptions.InvalidPasswordException, client.exceptions.InvalidParameterException, client.exceptions.UsernameExistsException, botocore.exceptions.ParamValidationError) as e:
        return {"Status": "Failed", "Response": str(e)}
    except (client.exceptions.CodeDeliveryFailureException) as e:
        pass

    return {"Status": "Success", "Response": response['UserSub']}

def saveUser(dynamodb, data):
    dynamodb.put_item(Item=data)
    return

def isUserAlreadySignedUp(dynamodb, username):

    response = dynamodb.get_item(Key={'username': username})
    if 'Item' in response:
        return True
    else:
        return False

def isQWAddressAlreadyTaken(qw_email, dynamodb):
    response = dynamodb.query(
        IndexName='sd-email',
        KeyConditionExpression=Key('quickwordz_email').eq(qw_email)
        )

    if 'Items' in response:
        if response['Items']:            
            return True
        else:
            return False
    else:
        return False

def generateQuickWordzEmail(email, dynamodb):
    qw_email = "%s@%s" % (email.split("@")[0], 'quickwordz.com')
    
    if isQWAddressAlreadyTaken(qw_email, dynamodb):
        QWAddressAlreadyTaken = True
        count = 1
        while QWAddressAlreadyTaken == True:
            qw_email_incremented = qw_email.split("@")[0] + str(count) + "@" + qw_email.split("@")[1]
            QWAddressAlreadyTaken = isQWAddressAlreadyTaken(qw_email_incremented, dynamodb)
            count+=1
        
        qw_email = qw_email_incremented
    return qw_email

def lambda_handler(event, context):
    print (event['body'])
    body = json.loads(event['body'])

    cognitoUserIdResponse = signUp(body['email'], body['password'])
    if cognitoUserIdResponse['Status'] == "Failed":
        response = {
            "statusCode": 400,
            "body": json.dumps(
                {
                    "status": cognitoUserIdResponse['Response']
                }
                ),
                    "headers": {
                        'Access-Control-Allow-Origin': '*'
                    }
        }
        return response

    dynamodb = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name'])

    quickwordz_email = generateQuickWordzEmail(body['email'], dynamodb)

    data = {
            "client_id": cognitoUserIdResponse['Response'],
            "username": body['username'], 
            "user_emails": body['email'],
            "quickwordz_email": quickwordz_email,
            "unverifiedEmailsLeft": os.environ['email_unverified_number_of_receives']
            }

    saveUser(dynamodb, data)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "status": '%s user has successfully signed up' % (body['username']),
                "quickwordz_email": quickwordz_email
            }
            ),
        "headers": {
            'Access-Control-Allow-Origin': '*'
        }
    }