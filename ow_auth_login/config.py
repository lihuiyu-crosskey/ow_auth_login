# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2017-5-3
Author: lihuiyu
"""
import os
from flask import Blueprint
blue = Blueprint('controllers', __name__,url_prefix='/auth_login')
beforeLogin=Blueprint('beforeLogin', __name__,url_prefix='/auth_login')
server=Blueprint('server', __name__,url_prefix='/auth_login')

basedir = os.path.abspath(os.path.dirname(__file__))
check=os.getenv('FLASK_CONFIG')
# check='test'
if check=='local':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=5556
    auth_verify_url = "http://127.0.0.1:2206"
    request_url = auth_verify_url+"/auth_verify/power/verify"
    sms_url="http://ysms.game2palm.com:8899/smsAccept/sendSms.action"
    db_set = {'name': 'root', 'password': 'ZTkj2018!', 'host': '192.168.1.203', 'port': '3306', 'db': 'zt_auth'}
    redis_set={'host':'192.168.1.203','port':'6379','db':'0'}
    redis_access_token = {'host': '192.168.1.203', 'port': '6379', 'db': '1'}
    redis_refresh_token = {'host': '192.168.1.203', 'port': '6379', 'db': '2'}
    redis_user_info = {'host': '192.168.1.203', 'port': '6379', 'db': '3'}
elif check=='online':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=5556
    auth_verify_url="http://192.168.1.202:3306"
    sms_url = "http://ysms.game2palm.com:8899/smsAccept/sendSms.action"
    request_url = auth_verify_url+"/auth_verify/power/verify"
    db_set = {'name': 'root', 'password': 'Wushuang2009!', 'host': '149.129.61.116', 'port': '3306',
              'db': 'auth_online'}
    redis_set = {'host': '149.129.61.116', 'port': '6179', 'password': 'admin123!', 'db': '0'}
    redis_access_token = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '1'}
    redis_refresh_token = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '2'}
    redis_user_info = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '3'}
elif check=='test':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=5556
    auth_verify_url = "http://192.168.1.205:2206"
    sms_url = "http://ysms.game2palm.com:8899/smsAccept/sendSms.action"
    request_url = auth_verify_url+"/auth_verify/power/verify"
    db_set = {'name': 'root', 'password': 'ZTkj2018!', 'host': '192.168.1.203', 'port': '3306', 'db': 'auth_test'}
    redis_set = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '0'}
    redis_access_token = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '1'}
    redis_refresh_token = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '2'}
    redis_user_info = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '3'}




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










