#!/usr/bin/env python3

import json
import boto3
import logging
import json
import argparse
import base64
from botocore.exceptions import ClientError

def get_ssm_params(region, param_name, with_decryption=False):
    """
    Get stored parameters from AWS SSM Parameter Store
    :param 'param' : parameter name to fetch details from AWS SSM
    :param 'with_decryption': return decrypted value for secured string params, ignored for String and StringList
    :return: Return parameter details if exist else None
    """
    
    ssm_client = boto3.client('ssm', region_name = region)

    try:
        response = ssm_client.get_parameter(
            Name=param_name,
            WithDecryption=with_decryption
        )
    except ClientError as e:
        logging.error(e)
        return None

    # correct response is dict
    return response

def get_secret(region, secret_name):
    """
    Get secrets from AWS Secrets Manager
    :param 'secret_name' : Secret name to fetch encrypted secrets from Secret Manager
    :return: Return parameter details if exist else None
    """
    # Sameple code snippet directly from AWS Secrets Manager

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region
    )

    # Code snippet to handle specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            return 
            # raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret


def main():

    parser = argparse.ArgumentParser(description="Get info from AWS Secrets Mgr and SSM Parameter Store.")
    parser.add_argument("region", type=str, help="AWS region to connect to")
    parser.add_argument("-p", "--param", type=str, help="get parameter from SSM Parameter Store")
    parser.add_argument("-s", "--secret", type=str, help="get secret info from Secrets Manager")

    args = parser.parse_args()

    region = args.region    # e.g. 'ap-southeast-1'
    ssm_param = args.param  # e.g. 'servername'
    secret = args.secret    # e.g. 'credential'

    if (ssm_param):
        hostname = get_ssm_params(region, ssm_param, False)
        print(f"AWS System Manager Parameters Store ({region})")
        if hostname == None:
            print(f"No parameter '{ssm_param}' from SSM Parameter Store")
        else:
            print(f"Parameter Name: {ssm_param}")
            print(f"Parameter Value: {hostname['Parameter']['Value']}")

    if (secret):
        login_credential = get_secret(region, secret)
        print(f"AWS Secrets Manager ({region}):")
        if login_credential == None:
            print(f"No secret '{secret}' from Secrets Manager") 
        else:
            username_pwd = json.loads(login_credential)
            print(f"Secrets Name: {secret}")
            print(f"Secrets (in JSON): {login_credential}")

            # Belows are the sample secrets key/value pairs
            print(f"Username: {username_pwd.get('username')}") 
            print(f"Password: {username_pwd.get('password')}")


if __name__ == '__main__':
    main()
