#!/usr/bin/env python
'''
Parse users from IAM and report on passwords and keys that have
not been utilized in (Variable X) days
'''

from datetime import datetime
import boto3
import botocore
import pytz

client = boto3.client('iam')

# base variables to modify as needed
SNS_TOPIC = 'UserAuditTopic'
key_usage = 30
passwd_usage = 30

def user_list():
    ''' Create list of IAM users by username '''
    a = []
    x = client.list_users()
    for i in x['Users']:
        a.append(i['UserName'])
    return a


def passwd_last_utilized():
    '''
    create dict of IAM accounts that have a password set,
    with date last utilized
    '''
    d = {}
    now = datetime.now(pytz.UTC)
    x = client.list_users()
    for i in x['Users']:
        try:
            r = client.get_login_profile(UserName=i['UserName'])
            s = client.get_user(UserName=i['UserName'])
            if 'CreateDate' in r['LoginProfile']:
                if 'PasswordLastUsed' in s['User']:
                    age = now - s['User']['PasswordLastUsed']
                    d[i['UserName']] = age.days
                else:
                    d[i['UserName']] = 'Never'
        except botocore.exceptions.ClientError as e:
            # if 'NoSuchEntity' then there is no password set, else raise error
            if 'NoSuchEntity' in e.response['Error']['Code']:
                pass
            else:
                raise e
    return d


def grab_key_list():
    ''' grab list of all keys for users '''
    d = {}
    users = user_list()
    for i in users:
        g = client.list_access_keys(UserName=i)
        d[i] = []
        for e in g['AccessKeyMetadata']:
            if e['AccessKeyId']:
                d[i].append(e['AccessKeyId'])
    return d


def key_last_utilized():
    '''
    parse through list of all keys, determining last time key was utilized
    '''
    d = {}
    now = datetime.now(pytz.UTC)
    key_list = grab_key_list()
    for keys, val in key_list.items():
        print key_list.items()
        for i in val:
            g = client.get_access_key_last_used(AccessKeyId=i)
            if 'LastUsedDate' in g['AccessKeyLastUsed']:
                age = now - g['AccessKeyLastUsed']['LastUsedDate']
                print keys, i, age.days
                d[keys] = ({i: age.days})
            else:
                d[keys] = ({i: "Never"})
    return d


if __name__ == '__main__':
    print key_last_utilized()
