import json
import os
import logging
import time
import sys
import re
import boto3
import datetime
import time
import email

from inspect import currentframe, getframeinfo

import base64
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

from Cryptodome.Cipher import AES
import requests

import mailparser
from bs4 import BeautifulSoup
from warnings import filterwarnings
filterwarnings("ignore")


sys.path.append('./lib')
import pushNotification

logger = logging.getLogger()
logger.setLevel(logging.INFO)
output_json = {}
skipplatformEndpoints = []


def get_line_number(frame):
    print_log("Executing Line Number %s" % (getframeinfo(frame).lineno))


def console_output(title=None, msg=None):
    if(title):
        if(msg):
            logger.info('{0}, {1}'.format(title, msg))
        else:
            logger.info('{0}'.format(title))
    else:
        logger.info('Executing on : {0},{1}'.format(get_line_number(currentframe()), msg))


def print_log(title=None, msg=None):
    if(title):
        if(msg):
            print_log(title + " : %s" % (msg))
        else:
            print_log(" %s" % (title))
    else:
        print_log("Executing on :" + get_line_number(currentframe()) + " %s" % (msg))


def KMSdecode(key, in_filename, iv, original_size, out_filename, chunksize=16 * 1024):
    with open(in_filename, 'rb') as infile:
        decryptor = AES.new(key, AES.MODE_GCM, iv)
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                # print_log("break")
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(original_size)


def decrementUnverifiedEmails(client_id, emails_left):
    boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).update_item(
        Key={
            'client_id': client_id,
        },
        UpdateExpression="set unverifiedEmailsLeft = :d",
        ExpressionAttributeValues={
            ':d': emails_left
        },
        ReturnValues="UPDATED_NEW"
    )
    return


def getUserEmailByQWEmail(qw_email):
    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
        IndexName='sd-email',
        KeyConditionExpression=Key('quickwordz_email').eq(qw_email)
    )

    return response['Items'][0]['user_emails']

def getClientIdByEmail(user_emails):
    print_log("user_emails ",user_emails)
    response = boto3.resource('dynamodb').Table('user-accounts-dev').query(
        IndexName='user_emails_index',
        KeyConditionExpression=Key('user_emails').eq(user_emails)
        )
    if response['Items']:
        if len(response['Items'])>0:
            return response['Items'][0]['User_sub_status']
        else:
            return False
    else:
        return False


def authorize(source, destination):
    print_log("authorize")
    print_log(source)
    print_log(destination)
    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
        IndexName='sd-email',
        KeyConditionExpression=Key('quickwordz_email').eq(destination)
    )

    print_log("authorize res")
    print_log(response)
    if 'Items' in response:
        if response['Items']:
            emails_left = int(response['Items'][0]['unverifiedEmailsLeft'])
            if emails_left > 0:
                decrementUnverifiedEmails(response['Items'][0]['client_id'], emails_left - 1)
                return True
            else:
                if destination in response['Items'][0]['quickwordz_email'] and (source in response['Items'][0]['user_emails'] or source == 'forwarding-noreply@google.com'):
                    return True
                else:
                    return False
    else:
        return False


def send_to_tse(email_body):
    # Send processed email to TSE
    url = os.environ['TSE_URL']
    payload = json.dumps({
        "text": email_body
    })
    headers = {
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        return "An Http Error occurred:" + repr(errh)
    except requests.exceptions.ConnectionError as errc:
        return "An Error Connecting to the API occurred:" + repr(errc)
    except requests.exceptions.Timeout as errt:
        return "A Timeout Error occurred:" + repr(errt)
    except requests.exceptions.RequestException as err:
        return "An Unknown Error occurred" + repr(err)

    summerised = json.loads(response.text)

    if summerised["message"] == "Success":
        return summerised

    return {}


def dynamoDB_connector(tablename, data):
    dynamodb = boto3.resource('dynamodb').Table(tablename)
    dynamodb.put_item(Item=data)


def update_expire_notification(username):
    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
        IndexName='username_index',
        KeyConditionExpression=Key('username').eq(username)
    )
    client_id = response['Items'][0]['client_id']
    iOS = response['Items'][0]['iOS']
    iOS.update({"send_expired_notification": False})
    boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).update_item(
        Key={
            'client_id': client_id,
        },
        UpdateExpression="set iOS = :value",
        ExpressionAttributeValues={
            ':value': iOS
        },
        ReturnValues="UPDATED_NEW"
    )


def getDevicesByUsername(username):
    skipplatformEndpoints.clear()
    try:
        response = boto3.resource('dynamodb').Table(os.environ['devices_table_name']).query(
            IndexName='username_index',
            KeyConditionExpression=Key('username').eq(username)
        )
        if 'Items' in response:
            if(response['Items'] and len(response["Items"]) > 0):
                print_log(response['Items'])
                return response["Items"]
    except Exception as e:
        print_log("Exception occured while checking subscription", e)
        return []


def skipPlatformEndPoint(devicesIds, app_platform, user):
    # all_devices = devicesIds.copy()
    print_log("all_devices", devicesIds)
    if devicesIds and len(devicesIds) > 0:
        for device in devicesIds:
            if "app_platform" in device and device["app_platform"] == app_platform:
                if app_platform == 'ios' and user["iOS"]["send_expired_notification"] == True:
                    pushNotification.send_ios_notification(device["gcm_endpoint"])
                    update_expire_notification(user["username"])
                print_log("skipped device", device)
                skipplatformEndpoints.append(device["gcm_endpoint"])
                # all_devices.remove(device)
    # for device in all_devices:
        # skipplatformEndpoints.append(device["gcm_endpoint"])
    print_log("skipplatformEndpoints", skipplatformEndpoints)
    print_log("skipplatformEndpoints length", len(skipplatformEndpoints))


def is_primary_account_active(primary_email):
    try:
        response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
            IndexName='user_emails_index',
            KeyConditionExpression=Key('user_emails').eq(primary_email)
        )
    except Exception as e:
        print_log(e)
    iOSExpiredTypes = ["101", "104"]
    androidExpiredTypes = ["13"]
    skippedPlatform = 0
    if 'Items' in response:
        if(response['Items'] and len(response["Items"]) > 0):
            print_log("existing primary_email")
            user = response["Items"][0]
            current_date_ms = int(round(time.time() * 1000))
            print_log("current_date_ms", current_date_ms)
            devicesIds = getDevicesByUsername(user["username"])
            if "iOS" in user:
                print_log("iOS info from user table")
                print_log(user["iOS"])
                if user["iOS"]["NotificationType"] in iOSExpiredTypes and user["iOS"]["auto_renew_status"] == "false":
                    if "expires_date_ms" in user["iOS"] and int(user["iOS"]["expires_date_ms"]) < current_date_ms:
                        print_log("ios device subscription has been expired")
                        skipPlatformEndPoint(devicesIds, "ios", user)
                        skippedPlatform = skippedPlatform + 1
                    if "NotificationType" not in user:
                        skippedPlatform = skippedPlatform + 1
                    print_log("iOS user account Expired or cancelled")
            if "NotificationType" in user:
                if user["NotificationType"] in androidExpiredTypes:
                    skipPlatformEndPoint(devicesIds, "android", user)
                    skippedPlatform = skippedPlatform + 1
                    if "iOS" not in user:
                        skippedPlatform = skippedPlatform + 1
                    print_log("Android user account Expired or cancelled")
            if skippedPlatform == 2:
                return False
            return True
        else:
            return False
    else:
        return False


def is_secondary_account_active(secondary_email):
    primary_email = None
    response = boto3.resource('dynamodb').Table(os.environ['secondary_users_emails']).query(
        KeyConditionExpression=Key('user_emails').eq(secondary_email)
    )
    if 'Items' in response:
        if(response['Items'] and len(response["Items"]) > 0):
            return response["Items"][0]
        else:
            return None
    else:
        return None


def forwardEmail(source_email, destination_email, body_email):

    client = boto3.client('ses')

    print_log("### %s" % (body_email))
    response = client.send_raw_email(

        Source=source_email,
        Destinations=[destination_email],
        RawMessage={
            'Data': body_email.as_string()
        }
    )

    print_log(response)
    return


def saveEmailMetadata(messageId, timestamp, exp_timestamp, email_model_data, primary_email):
    print_log("saveEmailMetadata trigger")
    email_model_data['timestamp'] = timestamp
    email_model_data['exp_timestamp'] = exp_timestamp
    email_model_data['message_id'] = messageId

    if "quickwordz.com" in email_model_data['to']:
        email_model_data['to'] = getUserEmailByQWEmail(email_model_data['to'])

    print_log("primary_email before saving")

    if primary_email == None:
        email_model_data['primary_email'] = email_model_data['to']
    else:
        email_model_data['primary_email'] = primary_email

    print_log(email_model_data['primary_email'])

    dynamoDB_connector(os.environ['emails_table_name'], email_model_data)
    return


def lambda_handler(event, context):
    message = json.loads(event['Records'][0]['Sns']['Message'])
    messageId = message['mail']['messageId']
    headers = message['mail']['headers']
    destination = message['mail']['destination'][0]
    double_fwd = False
    isSub = True
    exist_delivered_address = False
    double_fwd_destination = ""
    for header in headers:
        if header['name'] == 'Delivered-To' and exist_delivered_address == False:
            if destination == header['value']:
                destination = header['value']
            exist_delivered_address = True
        if header["name"] == "X-Forwarded-For":
            double_fwd = True
            fwds = header['value'].split()
            double_fwd_destination = fwds[len(fwds) - 1]
        if header['name'] == 'Content-Type':
            contentType = header['value']
    if double_fwd:
        destination = double_fwd_destination
    source = message['mail']['source']
    date = message['mail']['timestamp']
    primary_email = None

    if "quickwordz.com" not in destination:
        is_allowed = False
        print_log("quickwordz not in destination")
        if is_primary_account_active(destination) == True:
            is_allowed = True
        else:
            item = is_secondary_account_active(destination)
            if item:
                primary_email = item["primary_emails"]
                print_log("primary_email on secondary_email: ", primary_email)
                is_allowed = True
        if is_allowed == False:
            print_log("primary_email or secondary_email is not active... skipping to save and notification: ", messageId)
            return
    else:
        print_log("destination contains quickwordz.com")

    date_converted = datetime.datetime.strptime(date, '%Y-%m-%dT%H:%M:%S.%fZ')
    timestamp = date_converted.strftime("%s")
    exp_timestamp = int(timestamp) + int(os.environ['email_expiration_period_seconds'])

    if authorize(source, destination) == False:
        print_log("User account with %s email address does not exist" % (destination))
        return

    s3 = boto3.client('s3')
    object_info = s3.head_object(Bucket=os.environ['bucket_name'], Key=messageId)

    metadata = object_info['Metadata']

    envelope_key = base64.b64decode(metadata['x-amz-key-v2'])
    envelope_iv = base64.b64decode(metadata['x-amz-iv'])
    encrypt_ctx = json.loads(metadata['x-amz-matdesc'])
    original_size = metadata['x-amz-unencrypted-content-length']
    kms = boto3.client('kms')
    decrypted_envelope_key = kms.decrypt(CiphertextBlob=envelope_key, EncryptionContext=encrypt_ctx)
    s3.download_file(os.environ['bucket_name'], messageId, '/tmp/' + messageId)

    KMSdecode(decrypted_envelope_key['Plaintext'], '/tmp/' + messageId, envelope_iv, int(original_size), '/tmp/' + "decrypted-" + messageId)

    with open('/tmp/' + "decrypted-" + messageId, encoding="utf8", errors='ignore') as file:
        raw_email = mailparser.parse_from_file(file)

        if raw_email.text_plain:
            print_log("Email Processor: Plaintext message found.")
            mail_body = " ".join(raw_email.text_plain)
        else:
            print_log("Email Processor: HTML message found.")
            soup = BeautifulSoup(" ".join(raw_email.text_html), 'html.parser')
            mail_body = soup.get_text()

        summary = send_to_tse(mail_body)
        if summary:
            email_model_data = {'summary': summary['summary'], 'small_summary': summary['small_summary'], 'large_summary': email_model_data['large_summary']}

            saveEmailMetadata(messageId, timestamp, exp_timestamp, email_model_data, primary_email)
            platformEndpointArn = pushNotification.getPlatformEndpoint(destination, source, os.environ['user_accounts_table_name'], email_model_data["to"])
            print_log("platformEndpointArn :", platformEndpointArn)
            isSub = getClientIdByEmail(email_model_data["primary_email"])
            if platformEndpointArn:
                for platformEndpoint in platformEndpointArn:
                    if platformEndpoint not in skipplatformEndpoints:
                        pushNotification.send(email_model_data['from_username'], email_model_data['subject'], email_model_data['summary'], messageId, platformEndpoint, isSub)
            return
