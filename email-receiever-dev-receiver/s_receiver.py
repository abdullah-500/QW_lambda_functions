import serverless_sdk
sdk = serverless_sdk.SDK(
    org_id='yevhenii',
    application_name='quickwordz',
    app_uid='SMNLJ4Grjsk3M3zC0B',
    org_uid='T5QyGnJJGwlhV4TrHW',
    deployment_uid='3abfaab8-d65c-4c8d-a552-7270cc2f9347',
    service_name='email-receiever',
    should_log_meta=True,
    should_compress_logs=True,
    disable_aws_spans=False,
    disable_http_spans=False,
    stage_name='dev',
    plugin_version='4.1.2',
    disable_frameworks_instrumentation=False,
    serverless_platform_stage='prod'
)
handler_wrapper_kwargs = {'function_name': 'email-receiever-dev-receiver', 'timeout': 30}

try:
    user_handler = serverless_sdk.get_user_handler('functions/receiver/main.lambda_handler')
    handler = sdk.handler(user_handler, **handler_wrapper_kwargs)
except Exception as error:
    e = error
    def error_handler(event, context):
        raise e
    handler = sdk.handler(error_handler, **handler_wrapper_kwargs)
