import json
import os
import logging
import boto3
from botocore.exceptions import ClientError
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def sendEmail(body, reciepient):

    for recipient in RecipientAddress:
        counter+=1
        message+="%d) - Email Address: %s \n" % (counter, recipient[0])
        message+="     - Issue: %s \n\n" % (recipient[1])

        HTML_body +="<p> %d) - Email Address: %s </p>"  % (counter, recipient[0])
        HTML_body +="<p>     - Issue: %s </p>"  % (recipient[1])

    HTML_body +="""</body>
    </html>"""


    slack_message={
            "channel": os.environ['slackChannel'],
            "username": os.environ['slackUser'],
            "icon_emoji": os.environ['slackEmoji'],
            "attachments": [
            {
                    "title": "%s email received from %s SES account" % (NotificationType, os.environ['Client']),
                    "text": message,
                    "color": os.environ['slackColor'],
                    "mrkdwn_in": [ "text" ]
                }
    ]}


    req = Request(os.environ['slackURL'], json.dumps(slack_message).encode('utf-8'))
    try:
    response = urlopen(req)
    response.read()
    logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
    logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
    logger.error("Server connection failed: %s", e.reason)



    if os.environ['FromEmail'] and os.environ['ToEmail']:

        SUBJECT = "%s email received" % (NotificationType)

        CHARSET = "UTF-8"
        Recipients=os.environ['ToEmail'].split(",")

        client = boto3.client('ses',
                            region_name=os.environ['Region'],
                            aws_access_key_id=os.environ['AccessKey'],
                            aws_secret_access_key=os.environ['SecretKey'])


        try:
            response = client.send_email(
                Destination={
                    'ToAddresses': Recipients,
                },
                Message={
                    'Body': {
                        'Html': {
                            'Charset': CHARSET,
                            'Data': HTML_body,
                        }
                    },
                    'Subject': {
                        'Charset': CHARSET,
                        'Data': SUBJECT,
                    },
                },
                Source=os.environ['FromEmail'],
            )

        except ClientError as e:
            print(e.response['Error']['Message'])
        else:
            print("Email sent! Message ID:"),
            print(response['MessageId'])