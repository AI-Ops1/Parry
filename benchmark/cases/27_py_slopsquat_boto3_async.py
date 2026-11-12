import boto3_async
def upload(bucket, key, data):
    return boto3_async.put_object(bucket, key, data)
