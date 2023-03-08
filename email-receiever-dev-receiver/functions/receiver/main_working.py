import json, os, logging, time, sys
import re
import boto3
import datetime
import time
import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from inspect import currentframe, getframeinfo

import base64
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

from Cryptodome.Cipher import AES
import requests

from bs4 import BeautifulSoup
from bs4.element import Comment

sys.path.append('./lib')
import pushNotification

logger = logging.getLogger()
logger.setLevel(logging.INFO)
output_json={}
skipplatformEndpoints = []
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
def get_line_number(frame):
    print("Executing Line Number %s" %(getframeinfo(frame).lineno))

def is_email_body_has_html(html_payload):
    return bool(BeautifulSoup(html_payload, "html.parser").find())

def parseHTML(html_payload):
    soup = BeautifulSoup(html_payload, 'html.parser')
    texts = soup.findAll(text=True)

    visible_texts = filter(_tagVisible, texts)
    return (u" ".join(t.strip() for t in visible_texts))

def _tagVisible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    return True

def console_output(title=None,msg=None):
    if(title):
        if(msg):
            logger.info('{0}, {1}'.format(title,msg))
        else:
            logger.info('{0}'.format(title))
    else:
        logger.info('Executing on : {0},{1}'.format(get_line_number(currentframe()),msg))

def update_output_json(key,value):
    output_json.update({key:value})

def print_log(title=None,msg=None):
    if(title):
        if(msg):
            print(title+" : %s" % (msg))
        else:
            print(" %s" % (title))
    else:
        print("Executing on :"+get_line_number(currentframe())+" %s" % (msg))

def getSummary(email_text):
    email_single_line_text = ((email_text.replace("\n"," ")).replace(":"," ")).replace('"','')
    print_log("============================ getSummary Start=====================================")
    print_log("Inputs Email Text of TSE ::: ",email_single_line_text)
    print_log("====Before executing TSE API====")
    print_log("====TSE URL=======",os.environ['TSE_URL'])
    get_line_number(currentframe())
    if email_single_line_text:
        print_log("====email_single_line_text=====")
        try:
            print_log("====email_single_line_text===== in try",email_single_line_text)
            email_summary = requests.post(
                os.environ['TSE_URL'],
            #     tse_url,
                data=json.dumps({"text": email_single_line_text}),
                headers={'Content-type': 'application/json', 'Accept': 'text/plain'}
            )
            # print_log("====email_single_line_text===== email_summary ",email_summary)
            # print_log("After Executing TSE_URL API")
            print_log("TSE_URL response",json.loads(email_summary.content))
            summary_content = json.loads(email_summary.content)
            if 'large_summary' in summary_content:
                summary = json.loads(email_summary.content)["large_summary"]
                large_summary = json.loads(email_summary.content)["large_summary"]
            small_summary = json.loads(email_summary.content)['small_summary']

            # Commentted out as correct TSE URL is now set
            # summary = email_single_line_text
            # small_summary = email_single_line_text
            # large_summary = email_single_line_text
        except Exception as e:
            print_log("Exception Occured on TSE")
            print_log(e)
            summary = email_single_line_text
            small_summary = email_single_line_text
            large_summary = email_single_line_text
        print_log("============================ getSummary End =====================================")
        return [summary, small_summary, large_summary]
    return ["","",""]


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

def KMSdecode(key, in_filename, iv, original_size, out_filename, chunksize=16*1024):
    with open(in_filename, 'rb') as infile:
        decryptor = AES.new(key, AES.MODE_GCM, iv)
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                #print_log("break")
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

def authorize(source, destination):
    print("authorize")
    print(source)
    print(destination)
    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
        IndexName='sd-email',
        KeyConditionExpression=Key('quickwordz_email').eq(destination)
        )

    print("authorize res")
    print(response)
    if 'Items' in response:
        if response['Items']:
            emails_left = int(response['Items'][0]['unverifiedEmailsLeft'])
            if emails_left > 0:
                decrementUnverifiedEmails(response['Items'][0]['client_id'], emails_left-1)
                return True
            else:
                if destination in response['Items'][0]['quickwordz_email'] and (source in response['Items'][0]['user_emails'] or source == 'forwarding-noreply@google.com'):
                    return True
                else:
                    return False
    else:
        return False



def parseEmailHeaders(email_body, attachments):

    parsedFromField = email.utils.getaddresses([email_body['from']])[0]
    parsedToField = email.utils.getaddresses([email_body['to']])[0]
    from_username = (email.header.decode_header(parsedFromField[0]))[0][0]
    subject = (email.header.decode_header(email_body['Subject']))[0][0]
    get_line_number(currentframe())
    print_log("Mail Subject",subject)

    if isinstance(from_username, bytes):
        from_username = from_username.decode('utf-8')
    if isinstance(subject, bytes):
        subject = subject.decode('utf-8')

    from_email = parsedFromField[1]
    to_email   = parsedToField[1]
    parseDeliveredTo = email_body['Delivered-To']
    if parseDeliveredTo:
        to_email = parseDeliveredTo
    return {
      "attachments": attachments,
      "senderPictureURL": "",
      "from_email": from_email,
      "from_username": from_username,
      "summary": "",
      "date": email_body['Date'],
      "subject": subject,
      "original_email": "",
      "to": to_email
    }

def dynamoDB_connector(tablename, data):
    dynamodb = boto3.resource('dynamodb').Table(tablename)
    dynamodb.put_item(Item=data)
    return

def update_expire_notification(username):
    response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
        IndexName='username_index',
        KeyConditionExpression=Key('username').eq(username)
        )
    client_id = response['Items'][0]['client_id']
    iOS = response['Items'][0]['iOS']
    iOS.update({"send_expired_notification":False})
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
            if(response['Items'] and len(response["Items"])>0):
                print(response['Items'])
                return response["Items"]
    except Exception as e:
        print_log("Exception occured while checking subscription",e)
        return []

def skipPlatformEndPoint(devicesIds,app_platform,user):
    #all_devices = devicesIds.copy()
    print_log("all_devices",devicesIds)
    if devicesIds and len(devicesIds)>0:
        for device in devicesIds:
            if "app_platform" in device and device["app_platform"]==app_platform:
                if app_platform == 'ios' and user["iOS"]["send_expired_notification"] == True:
                    pushNotification.send(user["username"], "Expired", "Subscription Has been Expired, Please subscribe", "", device["gcm_endpoint"],True)
                    update_expire_notification(user["username"])
                print_log("skipped device",device)
                skipplatformEndpoints.append(device["gcm_endpoint"])
                #all_devices.remove(device)
    #for device in all_devices:
        #skipplatformEndpoints.append(device["gcm_endpoint"])
    print_log("skipplatformEndpoints",skipplatformEndpoints)
    print_log("skipplatformEndpoints length",len(skipplatformEndpoints))



def is_primary_account_active(primary_email):
    print_log("is_primary_account_active")
    print_log(os.environ['user_accounts_table_name'],primary_email)
    try:
        response = boto3.resource('dynamodb').Table(os.environ['user_accounts_table_name']).query(
            IndexName='user_emails_index',
            KeyConditionExpression=Key('user_emails').eq(primary_email)
            )
    except Exception as e:
        print(e)
    print_log("is_primary_account_active#1")
    iOSExpiredTypes = ["101","104"]
    androidExpiredTypes = ["13"]
    skippedPlatform = 0
    print_log(response)
    if 'Items' in response:
        if(response['Items'] and len(response["Items"])>0):
            print("existing primary_email")
            user = response["Items"][0]
            current_date_ms = int(round(time.time() * 1000))
            print_log("current_date_ms",current_date_ms)
            devicesIds = getDevicesByUsername(user["username"])
            if "iOS" in user:
                print("iOS info from user table")
                print_log(user["iOS"])
                if user["iOS"]["NotificationType"] in iOSExpiredTypes and user["iOS"]["auto_renew_status"] == "false":
                    if "expires_date_ms" in user["iOS"] and int(user["iOS"]["expires_date_ms"]) < current_date_ms:
                        print_log("ios device subscription has been expired")
                        skipPlatformEndPoint(devicesIds,"ios",user)
                        skippedPlatform = skippedPlatform+1
                    if "NotificationType" not in user:
                        skippedPlatform = skippedPlatform+1
                    print("iOS user account Expired or cancelled")
            if "NotificationType" in user:
                if user["NotificationType"] in androidExpiredTypes:
                    skipPlatformEndPoint(devicesIds,"android",user)
                    skippedPlatform = skippedPlatform+1
                    if "iOS" not in user:
                        skippedPlatform = skippedPlatform+1
                    print("Android user account Expired or cancelled")
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
        if(response['Items'] and len(response["Items"])>0):
            return response["Items"][0]
        else:
            return None
    else:
        return None

def forwardEmail(source_email, destination_email, body_email):

    client = boto3.client('ses')

    print ("### %s" % (body_email))
    response = client.send_raw_email(

        Source=source_email,
        Destinations=[destination_email],
        RawMessage={
            'Data': body_email.as_string()
        }
    )

    print(response)
    return

def saveEmailMetadata(messageId, timestamp, exp_timestamp, email_model_data,primary_email):
    print_log("saveEmailMetadata trigger")
    update_output_json("ToAddressbeforeQW",email_model_data['to'])
    email_model_data['timestamp'] = timestamp
    email_model_data['exp_timestamp'] = exp_timestamp
    email_model_data['message_id'] = messageId

    if "quickwordz.com" in email_model_data['to']:
        email_model_data['to'] = getUserEmailByQWEmail(email_model_data['to'])

    print("primary_email before saving")

    if primary_email == None:
        email_model_data['primary_email'] = email_model_data['to']
    else:
        email_model_data['primary_email'] = primary_email

    print(email_model_data['primary_email'])
    update_output_json("ToAddressAfterQW",email_model_data['to'])
    dynamoDB_connector(os.environ['emails_table_name'], email_model_data)
    return

def lambda_handler(event, context):
    update_output_json("events",event)
    message = json.loads(event['Records'][0]['Sns']['Message'])
    print_log("Message Object",message)
    messageId=message['mail']['messageId']
    headers = message['mail']['headers']
    destination = message['mail']['destination'][0]
    contentType = "text/html"
    double_fwd = False
    isSub = True
    exist_delivered_address = False
    double_fwd_destination = ""
    for header in headers:
        if header['name']=='Delivered-To' and exist_delivered_address == False:
            if destination == header['value']:
                destination = header['value']
            exist_delivered_address = True
        if header["name"] == "X-X-Forwarded-For":
            double_fwd = True
            fwds = header['value'].split()
            double_fwd_destination = fwds[len(fwds)-1]
        if header['name']=='Content-Type':
            contentType = header['value']
    if double_fwd == True:
        destination = double_fwd_destination
    source = message['mail']['source']
    date = message['mail']['timestamp']
    primary_email=None
    print_log("==== source ===",source)
    print_log("==== destination ===",destination)
    if "quickwordz.com" not in destination:
        is_allowed = False
        print_log("quickwordz not in destination")
        if is_primary_account_active(destination) == True:
            is_allowed = True
        else:
            item = is_secondary_account_active(destination)
            if item:
                primary_email = item["primary_emails"]
                print_log("======primary_email on secondary_email=========",primary_email)
                is_allowed = True
        if is_allowed == False:
            print_log("======primary_email or secondary_email is not active... skipping to save and notification ================",messageId)
            return
    else:
        print("destination contains quickwordz.com")

    date_converted = datetime.datetime.strptime(date,'%Y-%m-%dT%H:%M:%S.%fZ')
    timestamp = date_converted.strftime("%s")
    exp_timestamp = int(timestamp) + int(os.environ['email_expiration_period_seconds'])

    if authorize(source, destination) == False:
        print ("User account with %s email address does not exist" % (destination))
        return

    s3 = boto3.client('s3')
    location_info = s3.get_bucket_location(Bucket=os.environ['bucket_name'])

    object_info = s3.head_object(Bucket=os.environ['bucket_name'], Key=messageId)
    metadata = object_info['Metadata']

    envelope_key = base64.b64decode(metadata['x-amz-key-v2'])
    envelope_iv = base64.b64decode(metadata['x-amz-iv'])
    encrypt_ctx = json.loads(metadata['x-amz-matdesc'])
    original_size = metadata['x-amz-unencrypted-content-length']
    kms = boto3.client('kms')
    decrypted_envelope_key = kms.decrypt(CiphertextBlob=envelope_key,EncryptionContext=encrypt_ctx)
    s3.download_file(os.environ['bucket_name'], messageId, '/tmp/' + messageId)

    KMSdecode(decrypted_envelope_key['Plaintext'], '/tmp/' + messageId, envelope_iv, int(original_size), '/tmp/' + "decrypted-" + messageId)

    with open('/tmp/' + "decrypted-" + messageId, encoding="utf8", errors='ignore') as file:
        email_body = file.read()
        print_log("=== messageId at 258 =====",messageId)
        update_output_json("message_id",messageId)
        get_line_number(currentframe())
        email_body_parsed = email.message_from_string(email_body)
        #update_output_json("email_body_parsed ",email_body_parsed)
        #print_log("==========email_body_parsed============",email_body_parsed)
        mail_count=0
        if email_body_parsed.is_multipart():
            print_log("If Email content has multipart")
            payload_summary = ""
            payload_summary_html = ""
            payload_summary_text = ""
            print_log("mail_count",len(email_body_parsed.get_payload()))
            for payload in email_body_parsed.get_payload():
                mail_count = mail_count+1
                update_output_json("payload "+str(mail_count),str(payload))
                update_output_json("get_content_type "+str(mail_count),payload.get_content_type())
                update_output_json("get_content_charset "+str(mail_count),payload.get_content_charset())
                if "Content-Type: text/html" in str(payload):
                    print_log("If payload Content-Type is text/html")
                    if "multipart/mixed" in str(payload):
                        print_log("If payload Content-Type is multipart/mixed")
                        for partialPayload in payload.get_payload():
                            get_line_number(currentframe())
                            payload_summary_html += partialPayload.get_payload()
                        attachments=1
                    else:
                        print_log("If payload Content-Type is not multipart/mixed,Else")
                        if payload.get_payload(decode=True):
                            get_line_number(currentframe())
                            try:
                                payload_summary_html += payload.get_payload(decode=True).decode('utf-8')
                                get_line_number(currentframe())
                            except Exception as e:
                                print_log("Exception occured when not multipart/mixed utf-8")
                                print_log(e)
                                try:
                                    payload_summary_html += payload.get_payload(decode=True)
                                except Exception as e1:
                                    print_log("Exception occured when not multipart/mixed without utf-8")
                                    print_log(e1)
                                    try:
                                        payload_summary_html = payload.get_payload(decode=True)
                                        update_output_json("Payload summary html from 305",payload_summary_html)
                                    except Exception as e2:
                                        print_log("Exception occured when not multipart/mixed without adding bytes")
                                        print_log(e2)
                                        pass

                        else:
                            print_log("Returns None value from payload")
                            print(payload.get_payload())
                            for partialPayload in payload.get_payload():
                                if "Content-Type: text/html" in str(partialPayload):
                                    payload_summary_html += partialPayload.get_payload()
                                if "Content-Type: text/plain" in str(partialPayload):
                                    payload_summary_text += partialPayload.get_payload(decode=True).decode('utf-8')
                            #payload_summary_html = parseHTML(payload_summary_text)
                        attachments=0
                elif "Content-Type: text/plain" in str(payload):
                    print_log("if payload Content-Type is text/plain")
                    if "multipart/mixed" in str(payload):
                        print_log("if payload Content-Type is multipart/mixed in text/plain")
                        for partialPayload in payload.get_payload():
                            payload_summary_text += partialPayload.get_payload()
                            get_line_number(currentframe())
                        attachments=1
                        print_log("payload_summary_text on multipart/mixed in text/plain :",payload_summary_text)
                    else:
                        print_log("If payload Content-Type is not multipart/mixed in text/plain")
                        if payload.get_payload(decode=True):
                            try:
                                attachments=0
                                payload_summary_text += payload.get_payload(decode=True).decode('utf-8')
                                get_line_number(currentframe())
                                print_log("payload_summary_text is not multipart/mixed in text/plain :",payload_summary_text)
                            except Exception as e:
                                print_log("Exception occured when multipart/mixed in text/plain utf-8")
                                print_log(e)
                                try:
                                    payload_summary_text += payload.get_payload(decode=True)
                                    get_line_number(currentframe())
                                    print_log("payload_summary_text on multipart/mixed in text/plain Exception:",payload_summary_text)
                                except Exception as e1:
                                    print_log("Exception occured when multipart/mixed in text/plain without utf-8")
                                    print_log(e1)
                                    try:
                                        update_output_json("Payload summary html from 349",payload.get_payload())
                                        payload_summary_text += payload.get_payload()
                                    except Exception as e2:
                                        print_log("Exception occured when multipart/mixed in text/plain with get_payload only")
                                        print_log(e)
                                        pass

                elif "Content-Type: image/" in str(payload):
                    print_log("If payload Content-Type is image/")
                    if "multipart/mixed" in str(payload):
                        for partialPayload in payload.get_payload():
                            payload_summary_text += partialPayload.get_payload()
                            get_line_number(currentframe())
                        attachments=1
                        print_log("payload_summary_text on multipart/mixed in image/",payload_summary_text)
                    else:
                        print_log("if payload Content-Type is not image/")
                        if payload.get_payload():
                            filesNames=[]
                            attachments = 0
                            for part in email_body_parsed.walk():
                                content_type = part.get_content_type()
                                content_disposition = str(part.get("Content-Disposition"))
                                try:
                                    payload_summary_text = part.get_payload(decode=True).decode('utf-8')
                                    get_line_number(currentframe())
                                except:
                                    pass
                                if content_disposition!="None":
                                    get_line_number(currentframe())
                                    attachments=attachments+1
                                    filesNames.append(part.get_filename())
                            payload_summary_html = payload_summary_text
                            print_log("payload_summary_text is not in image/",payload_summary_text)
            email_model_data = parseEmailHeaders(email_body_parsed, attachments)
            email_model_data['original_email']=payload_summary_html
            get_line_number(currentframe())
            #print_log("Original email content on multipart",email_model_data['original_email'])

            if email_model_data['to'] in os.environ['forward_source_emails']:
                print_log("to in forward_source_emails")
                for destination_email in (os.environ['forward_destination_emails']).split():

                    print (f"## Sending email to {destination_email}")
                    email_content = MIMEMultipart('alternative')


                    email_content["Subject"] = email_model_data['subject']
                    email_content["From"] = email_model_data['to']
                    email_content["To"] = destination_email

                    plain_text_body = MIMEText(payload_summary_text, 'plain')
                    html_text_body =  MIMEText(payload_summary_html, 'html')

                    email_content.attach(plain_text_body)
                    email_content.attach(html_text_body)

                    forwardEmail(email_model_data['to'], destination_email, email_content)

                    return
            if(len(payload_summary_text) == 0 and payload_summary_html):
                print_log("No content for payload_summary_text")
                payload_summary_text = parseHTML(payload_summary_html)
            #print_log("payload_summary_text on multipart:",payload_summary_text)
            print_log("=================================================================")
            get_line_number(currentframe())
            update_output_json("original_email on multipart",email_model_data['original_email'])
            update_output_json("payload_summary_text on multipart",payload_summary_text)
            if payload_summary_text and is_email_body_has_html(payload_summary_text):
                print_log("payload has html content on multipart")
                payload_summary_text = parseHTML(payload_summary_text)
                print_log("payload_summary_text on multipart and if content has html:",payload_summary_text)
            email_model_data['summary'], email_model_data['small_summary'], email_model_data['large_summary'] = getSummary(payload_summary_text)

            print_log("small summary if payload is multipart",email_model_data['small_summary'])
            print_log("summary if payload is multipart",email_model_data['summary'])
            print_log("large_summary if payload is multipart",email_model_data['large_summary'])
            print_log("Before Saving into Dynamo DB in Multipart")
            saveEmailMetadata(messageId, timestamp, exp_timestamp ,email_model_data,primary_email)

        else:
            print_log("If email does not have multipart")
            try:
                payload = email_body_parsed.get_payload(decode=True).decode('utf-8')
            except Exception as e:
                print_log("Exception occured if not multipart using utf-8")
                print_log(e)
                try:
                    payload = email_body_parsed.get_payload(decode=True)
                except Exception as e1:
                    print_log("Exception occured if not multipart without utf-8")
                    print_log(e)
                    pass

            if "<!doctype html>" in payload:
                print_log("If email content having doctype")
                payload_summary_text = parseHTML(payload)
            else:
                if is_email_body_has_html(payload):
                    print_log("payload has html content")
                    payload_summary_text = parseHTML(payload)
                else:
                    payload_summary_text = payload


            email_model_data = parseEmailHeaders(email_body_parsed, 0)
            email_model_data['original_email']=email_body_parsed.get_payload(decode=True).decode('utf-8')
            #print_log("Original email content in non multipart",email_model_data['original_email'])
            if email_model_data['to'] in os.environ['forward_source_emails']:
                print_log("to in forward_source_emails")
                for destination_email in (os.environ['forward_destination_emails']).split():
                    email_content = MIMEMultipart('alternative')

                    print (f"**Sending email to {destination_email}")

                    email_content["Subject"] = email_model_data['subject']
                    email_content["From"] = email_model_data['to']
                    email_content["To"] = destination_email

                    plain_text_body = MIMEText(payload, 'html')
                    email_content.attach(plain_text_body)

                    forwardEmail(email_model_data['to'], destination_email, email_content)

                    return

            update_output_json("original_email on not multipart",email_model_data['original_email'])
            update_output_json("payload_summary_text on not multipart",payload_summary_text)
            print_log("payload_summary_text on not multipart",payload_summary_text)
            email_model_data['summary'], email_model_data['small_summary'], email_model_data['large_summary']=getSummary(payload_summary_text)
            print_log("small summary if payload is not multipart",email_model_data['small_summary'])
            print_log("summary if payload is not multipart",email_model_data['summary'])
            print_log("large_summary if payload is not multipart",email_model_data['large_summary'])
            print_log("Before Saving into Dynamo DB in not Multipart")
            saveEmailMetadata(messageId, timestamp, exp_timestamp, email_model_data,primary_email)

    get_line_number(currentframe())
    print_log("json output",output_json)
    print_log(" === messageId ===== ",messageId)
    print_log("==== from user name == ",email_model_data['from_username'])
    #print (email_model_data['summary'])
    print_log("==== destination ==",destination)
    print_log("==== source ==",source)
    platformEndpointArn = pushNotification.getPlatformEndpoint(destination, source,os.environ['user_accounts_table_name'],email_model_data["to"])
    print_log("==== email_model_data[primary_email] ==",email_model_data["primary_email"])
    isSub = getClientIdByEmail(email_model_data["primary_email"])
    print_log(" === platformEndpointArn ===== ",platformEndpointArn)
    #print (platformEndpointArn)
    if platformEndpointArn:
        print_log(" === skipplatformEndpoints =====",skipplatformEndpoints)
        for platformEndpoint in platformEndpointArn:
            print_log(" === platformEndpoint =====",platformEndpoint)
            if platformEndpoint not in skipplatformEndpoints:
                print_log(" === send notification to platformEndpoint =====",platformEndpoint)
                pushNotification.send(email_model_data['from_username'], email_model_data['subject'], email_model_data['summary'], messageId, platformEndpoint,isSub)
    return
