#!/usr/bin/env python
"""
Parse users from IAM and verify that password and
access key are less than X days old
"""

from datetime import datetime
import boto3
import botocore
import pytz

client = boto3.client('iam')

x = client.list_users()


def user_list():
    ''' Create list of IAM users by username '''
    a = []
    for i in x['Users']:
        a.append(i['UserName'])
    return a


def passwd_last_used():
    '''
    create dict of IAM accounts that have last used time stamp on password
    '''
    d = {}
    for i in x['Users']:
        if 'PasswordLastUsed' in i:
            d[i['UserName']] = i['PasswordLastUsed']
    return d


def passwd_creation_date():
    '''
    create dict of IAM accounts that have a password set, with date of creation
    '''
    d = {}
    for i in x['Users']:
        try:
            r = client.get_login_profile(UserName=i['UserName'])
            if 'CreateDate' in r['LoginProfile']:
                d[i['UserName']] = r['LoginProfile']['CreateDate']
        except botocore.exceptions.ClientError:
            pass
    return d


def get_passwd_age():
    ''' print users with day count since password last used '''
    d = {}
    now = datetime.now(pytz.UTC)
    plist = passwd_creation_date()
    print(plist)
    for i in plist:
        age = now - plist[i]
        d[i] = age.days
    return d


print(get_passwd_age())
