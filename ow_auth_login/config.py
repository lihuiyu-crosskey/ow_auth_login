# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2017-5-3
Author: lihuiyu
"""
import os


basedir = os.path.abspath(os.path.dirname(__file__))
check=os.getenv('FLASK_CONFIG')
# check='online'
if check=='local':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=5555
    auth_verify_url = "http://127.0.0.1:5556"
    request_url = auth_verify_url+"/auth_verify/power/verify"
    save_apis_url = auth_verify_url + "/auth_verify/server/apis/save"
    sms_url="http://ysms.game2palm.com:8899/smsAccept/sendSms.action"
    db_set = {'name': 'root', 'password': 'ZTkj2018!', 'host': '192.168.1.203', 'port': '3306', 'db': 'zt_auth'}
    redis_set={'host':'192.168.1.203','port':'6379','db':'15', 'password': 'admin123!'}

elif check=='online':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=5555
    auth_verify_url="http://39.100.138.101:5556"
    sms_url = "http://ysms.game2palm.com:8899/smsAccept/sendSms.action"
    request_url = auth_verify_url+"/auth_verify/server/power/verify"
    save_apis_url=auth_verify_url+"/auth_verify/server/apis/save"
    db_set = {'name': 'root', 'password': 'Admin123456!', 'host': '39.100.138.101', 'port': '3306',
              'db': 'ow_auth'}
    redis_set = {'host': '39.100.138.101', 'port': '6379', 'password': 'admin123!', 'db': '0'}

elif check=='test':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=5555
    auth_verify_url = "http://192.168.1.204:5556"
    sms_url = "http://ysms.game2palm.com:8899/smsAccept/sendSms.action"
    request_url = auth_verify_url+"/auth_verify/power/verify"
    save_apis_url = auth_verify_url + "/auth_verify/server/apis/save"
    db_set = {'name': 'root', 'password': 'ZTkj2018!', 'host': '192.168.1.203', 'port': '3306', 'db': 'auth_test'}
    redis_set = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '15'}





sqlalchemy_set={'SQLALCHEMY_ECHO':True,'SQLALCHEMY_POOL_SIZE':10,'SQLALCHEMY_POOL_RECYCLE':5,'SQLALCHEMY_DATABASE_URI':"mysql://%s:%s@%s:%s/%s"%(db_set['name'],db_set['password'],db_set['host'],db_set['port'],db_set['db']),
                'SQLALCHEMY_TRACK_MODIFICATIONS':True,'SQLALCHEMY_COMMIT_TEARDOWN':True}
mail_set={}
    # MAIL_SERVER = 'email-smtp.us-west-2.amazonaws.com'
    # MAIL_PROT = 587
    # MAIL_USE_TLS = True
    # MAIL_USE_SSL = False
    # MAIL_USERNAME = "AKIAIXEVFGVWK7ILOO6A"
    # MAIL_PASSWORD = "AjAtYAjw8J5IgP8c4zckZQNDsCMhvW6gw0WkX1KjhQGV"
    # MAIL_DEBUG = True










