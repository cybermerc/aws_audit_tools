#!/usr/bin/env python
"""
Parse users from IAM and verify that password and
access key are less than 90 days old
"""

import boto3

client = boto3.client('iam')

x = client.list_users()
a = []


def user_list():
    for i in x['Users']:
        a.append(i['UserName'])
    return a


def is_passwd_set():
    d = {}
    for i in x['Users']:
        if 'PasswordLastUsed' in i:
            y = i['PasswordLastUsed']
        else:
            y = 'false'
        d[i['UserName']] = y
    print(d)

is_passwd_set()
