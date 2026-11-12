import boto3
def upload(bucket, key, data):
    s3 = boto3.client('s3')
    return s3.put_object(Bucket=bucket, Key=key, Body=data)
