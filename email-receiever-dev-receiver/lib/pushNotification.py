import boto3
import os
import json
from datetime import datetime
from boto3.dynamodb.conditions import Key


def getPlatformEndpoint(user_email, source, table, toAddress):

    print("PlatformEndpoint user email: ", user_email, toAddress)

    if "quickwordz.com" in user_email and toAddress:
        user_email = toAddress

    if "quickwordz" in user_email and toAddress is None:
        response = (
            boto3.resource("dynamodb")
            .Table(os.environ["user_accounts_table_name"])
            .scan(
                IndexName="sd-email",
                FilterExpression=Key("quickwordz_email").eq(user_email),
            )
        )
        user_email = response["Items"][0]["user_emails"]

    response = (
        boto3.resource("dynamodb")
        .Table(table)
        .scan(
            IndexName="user_emails_index",
            FilterExpression=Key("user_emails").eq(user_email),
        )
    )

    print("PlatformEndpoint response: ", response)

    if "Items" in response:
        print("PlatformEndpoint Items", response["Items"])
        if response["Items"] and response["Count"] > 0:
            length = len(response["Items"])
            if "gcm_endpoint" in response["Items"][length - 1]:
                return response["Items"][length - 1]["gcm_endpoint"]
            else:
                return False
        else:
            return getSecondaryPlatformEndpoint(user_email)
    else:
        print("No Items on PlatformEndpoint")
        return False


def getSecondaryPlatformEndpoint(user_email):
    response = (
        boto3.resource("dynamodb")
        .Table("secondary_users_emails")
        .scan(FilterExpression=Key("user_emails").eq(user_email))
    )

    if "Items" in response:
        if response["Items"] and response["Count"] > 0:
            length = len(response["Items"])
            if "primary_emails" in response["Items"][length - 1]:
                primary_emails_items = (
                    boto3.resource("dynamodb")
                    .Table(os.environ["user_accounts_table_name"])
                    .scan(
                        IndexName="user_emails_index",
                        FilterExpression=Key("user_emails").eq(
                            response["Items"][length - 1]["primary_emails"]
                        ),
                    )
                )
                if "Items" in primary_emails_items:
                    print(
                        "getSecondaryPlatformEndpoint Items %s"
                        % (primary_emails_items["Items"])
                    )
                    if (
                        primary_emails_items["Items"]
                        and len(primary_emails_items["Items"]) > 0
                    ):
                        return primary_emails_items["Items"][length - 1]["gcm_endpoint"]
                    else:
                        return False
                else:
                    return False
            else:
                return False
    else:
        print("No Items on PlatformEndpoint")
        return False


def send(title, subtitle, body, email_id, arn, isSb):

    sns = boto3.resource("sns")

    if isSb:
        body = ((body.replace("\n", " ")).replace(":", " ")).replace('"', "")
        title = ((title.replace("\n", " ")).replace(":", " ")).replace('"', "")
    else:
        title = ((title.replace("\n", " ")).replace(":", " ")).replace('"', "")
        subtitle = "You received a new email"
        body = "Please update your subscription"

    message = {
        "GCM": '{ "notification": { "body": "%s", "subtitle": "%s",  "title":"%s", "sound": "default" }, "data": { "emailID": "%s", "notification_foreground": "true" }}'
        % (body, subtitle, title, email_id)
    }

    print(message)
    platform_endpoint = sns.PlatformEndpoint("arn")

    try:
        response = platform_endpoint.publish(
            TargetArn=arn, Message=json.dumps(message)[:4062], MessageStructure="json"
        )
        print("successfully sent")
    except (
        boto3.client("sns").exceptions.EndpointDisabledException,
        boto3.client("sns").exceptions.InvalidParameterException,
    ) as e:
        print("Endpoint is disabled")
        print(e)
        pass

    return


def send_ios_notification(arn):
    sns = boto3.resource("sns")
    notificationType = "EXPIRED"
    expires_date = datetime.now()
    message = {
        "GCM": '{ "notification": { "body": "%s", "notificationType":"%s", "sound": "default" }, "data": {"notification_foreground": "true","body": "%s", "notificationType":"%s", "expires_date":"%s"}}'
        % (
            str(notificationType),
            notificationType,
            str(notificationType),
            notificationType,
            expires_date,
        )
    }
    print(message)
    platform_endpoint = sns.PlatformEndpoint("arn")
    try:
        response = platform_endpoint.publish(
            TargetArn=arn, Message=json.dumps(message)[:4062], MessageStructure="json"
        )
        print("successfully sent")
    except (
        boto3.client("sns").exceptions.EndpointDisabledException,
        boto3.client("sns").exceptions.InvalidParameterException,
    ) as e:
        print("Endpoint is disabled")
        print(e)
        pass

    return
