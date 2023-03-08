import boto3
import json
import os 


def lambda_handler(event, context):

    print (event)
    print (event['triggerSource'])
    if event['triggerSource'] == 'CustomMessage_ForgotPassword':
        message = "Your verification code is %s" % (event['request']['codeParameter'])
    else:
        message = "Your registration has been successfully verified"
        event['response']['autoConfirmUser'] = True
        event['response']['autoVerifyEmail'] = True
        # Uncomment to enable verification
        # message = "Your verification URL is https://hteferopa3.execute-api.us-east-1.amazonaws.com/dev/confirm?email=%s&confirmationCode=%s" % (event['request']['userAttributes']['email'], event['request']['codeParameter'])

    # event['response']['smsMessage'] = message
    # event['response']['emailMessage'] = message
    # event['response']['emailSubject'] = "Successfull registration"

    return event