#!/usr/bin/env python
"""
Parse users from IAM and report on passwords and
access keys that are older than (variable X) days
"""

from datetime import datetime
import boto3
import botocore
import pytz

client = boto3.client('iam')

max_key_age = 90
max_passwd_age = 90

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
    ''' get users with day count since password last used '''
    d = {}
    now = datetime.now(pytz.UTC)
    plist = passwd_creation_date()
    for i in plist:
        age = now - plist[i]
        d[i] = age.days
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
    passwd_list = get_passwd_age()
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

if __name__ == '__main__':
    t = generate_report()
    print t
