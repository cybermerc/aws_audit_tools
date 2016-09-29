#!/usr/bin/env python
'''
Parse users from IAM and report on passwords and
access keys that are older than 90 days
'''

from datetime import datetime
import time
import StringIO
import csv
import boto3
import botocore
import pytz

client = boto3.client('iam')

# base variables to modify as needed
SNS_TOPIC = 'UserAudit'
max_key_age = 9
max_passwd_age = 9


def user_list():
    ''' Create list of IAM users by username '''
    a = []
    x = client.list_users()
    for i in x['Users']:
        a.append(i['UserName'])
    return a


def parse_report():
    '''
    Grab IAM credential report and parse to grab data not available via boto3
    specifically password_last_changed date for password age evaluation
    '''
    report = None
    while report is None:
        try:
            report = client.get_credential_report()
        except botocore.exceptions.ClientError as e:
            if 'ReportNotPresent' in e.message:
                pass
            else:
                raise e
            time.sleep(5)
    document = StringIO.StringIO(report['Content'])
    reader = csv.DictReader(document)
    report_rows = []
    for row in reader:
        report_rows.append(row)
    return report_rows


def passwd_last_changed():
    '''
    Parse list of users with password enabled and determine one that have not
    been changed in X days
    '''
    d = {}
    report = parse_report()
    users = user_list()
    now = datetime.now()
    for user in users:
        for row in report:
            if row['user'] == user:
                if row['password_enabled'] == 'true':
                    age = now - datetime.strptime(row['password_last_changed'][:-15], "%Y-%m-%d")
                    d[user] = age.days
    return d


def grab_key_list():
    ''' grab access keys for a list of users and determine age of keys '''
    d = {}
    now = datetime.now(pytz.UTC)
    users = user_list()
    for i in users:
        g = client.list_access_keys(UserName=i)
        d[i] = []
        for e in g['AccessKeyMetadata']:
            if e['AccessKeyId']:
                age = now - e['CreateDate']
                d[i].append({e['AccessKeyId']: age.days})
    return d


def old_passwds():
    ''' Check passwd_list and flag all passwds older than X '''
    passwd_list = passwd_last_changed()
    d = {}
    for key, val in passwd_list.items():
        if val > max_passwd_age:
            d[key] = val
    return d


def old_keys():
    ''' Check list of user keys and flag all keys older than X '''
    key_list = grab_key_list()
    d = {}
    for key, val in key_list.items():
        for k in val:
            for a, b in k.items():
                if b > max_key_age:
                    d[key] = (a, b)
    return d


def passwd_report_text():
    ''' Create report text of passwd ages '''
    op = old_passwds()
    op_text = "\n\nAccounts with passwords older than "
    op_text += str(max_passwd_age) + " days"
    op_text += "\nAccount name / Age of password in days\n"
    for k, v in op.items():
        op_text += "\n" + k + " / " + str(v)
    return op_text


def key_report_text():
    ''' Create report text of key age '''
    ok = old_keys()
    ok_text = "\n\n\nAccounts with Keys older than "
    ok_text += str(max_key_age) + " days"
    ok_text += "\nAccount name / Key / Age of Key in days\n"
    for key, val in ok.items():
        ok_text += "\n" + str(key) + " / "
        ok_text += val[0] + " / " + str(val[1])
    return ok_text


def generate_report():
    ''' Create complete text of report '''
    op = passwd_report_text()
    ok = key_report_text()
    report = "\nUser password and key age report for "
    report += datetime.now().strftime("%Y-%m-%d") + "\n"
    report += op
    report += ok
    return report

def publish_report():
    ''' Publish report to SNS topic '''
    report = generate_report()
    pub = boto3.client('sns')
    resp = pub.list_topics()
    msg_subject = 'Daily AWS password and key age report'
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
