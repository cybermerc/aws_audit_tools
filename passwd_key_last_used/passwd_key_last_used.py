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
    a = [u['UserName'] for u in client.list_users()['Users']]
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
                    d[i['UserName']] = 'Never Used'
        except botocore.exceptions.ClientError as e:
            # if 'NoSuchEntity' then there is no password set, else raise error
            if 'NoSuchEntity' in e.response['Error']['Code']:
                pass
            else:
                raise e
    return d

def old_passwds():
    ''' Check passwd_list and flag all passwords not used in X days '''
    passwd_list = passwd_last_utilized()
    d = {}
    for key, val in passwd_list.items():
        if val == 'Never Used':
            d[key] = val
        elif val > passwd_usage:
            d[key] = val
    return d


def key_last_utilized():
    ''' grab access keys for a list of users and determine last utilization '''
    d = {}
    now = datetime.now(pytz.UTC)
    users = user_list()
    for i in users:
        g = client.list_access_keys(UserName=i)
        d[i] = []
        for e in g['AccessKeyMetadata']:
            if e['AccessKeyId']:
                r = client.get_access_key_last_used(AccessKeyId=e['AccessKeyId'])
                if 'LastUsedDate' in r['AccessKeyLastUsed']:
                    age = now - r['AccessKeyLastUsed']['LastUsedDate']
                    d[i].append({e['AccessKeyId']: age.days})
                else:
                    d[i].append({e['AccessKeyId']: "Never Used"})
    return d


def old_keys():
    ''' Check list of user keys and flag all keys not used in X days '''
    key_list = key_last_utilized()
    d = {}
    for key, val in key_list.items():
        d[key] = []
        for k in val:
            for a, b in k.items():
                if b == 'Never Used':
                    d[key].append({a: b})
                elif b > key_usage:
                    d[key].append({a: b})
    return d


def generate_passwd_report():
    ''' Generate report of all passwords not utilized in X days '''
    op = old_passwds()
    op_text = "\n\nAccounts with passwords not utilized in "
    op_text += str(passwd_usage) + " days"
    op_text += "\nAccount name / Days since list utilization\n"
    for k, v in op.items():
        op_text += "\n" + k + " / " + str(v)
    return op_text


def generate_key_report():
    ''' Generate report of all keys not utilized in X days '''
    ok = old_keys()
    ok_text = "\n\n\nAccounts with Keys not utilized in "
    ok_text += str(key_usage) + " days"
    ok_text += "\nAccount name / Key / Days since Key Used\n"
    for key, val in ok.items():
        for v in val:
            for a, b in v.items():
                ok_text += "\n" + str(key) + " / "
                ok_text += str(a) + " / " + str(b)
    return ok_text

def generate_report():
    ''' Create complete text of report '''
    op = generate_passwd_report()
    ok = generate_key_report()
    report = "\nUser password and key Utilization report for "
    report += datetime.now().strftime("%Y-%m-%d") + "\n"
    report += op
    report += ok
    return report


def publish_report():
    ''' Publish report to SNS topic '''
    report = generate_report()
    pub = boto3.client('sns')
    resp = pub.list_topics()
    msg_subject = 'Daily AWS password and key usage report'
    topic_arn = ''
    for topic in resp['Topics']:
        if SNS_TOPIC in topic['TopicArn']:
            topic_arn = topic['TopicArn']
    if topic_arn == '':
        raise "Topic %s not found" % SNS_TOPIC
    pub.publish(TopicArn=topic_arn, Subject=msg_subject, Message=report)


def my_handler(event, context):
    ''' Lambda execute function '''
    publish_report()
