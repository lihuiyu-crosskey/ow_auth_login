# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2017-5-3
Author: lihuiyu
"""
import os

basedir = os.path.abspath(os.path.dirname(__file__))
check=os.getenv('FLASK_CONFIG')
# check='test'
if check=='local':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=2205
    auth_verify_url = "http://127.0.0.1:2206"
    request_url = auth_verify_url+"/auth_verify/power/verify"
    sms_url="http://ysms.game2palm.com:8899/smsAccept/sendSms.action"
    db_set = {'name': 'root', 'password': 'ZTkj2018!', 'host': '192.168.1.203', 'port': '3306', 'db': 'zt_auth'}
    # db_set = {'name': 'root', 'password': 'ZTkj2018!', 'host': '192.168.1.203', 'port': '3306', 'db': 'zt_auth_online'}
    redis_set={'host':'192.168.1.203','port':'6379','db':'0'}
    redis_access_token = {'host': '192.168.1.203', 'port': '6379', 'db': '1'}
    redis_refresh_token = {'host': '192.168.1.203', 'port': '6379', 'db': '2'}
    redis_user_info = {'host': '192.168.1.203', 'port': '6379', 'db': '3'}
elif check=='online':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=3305
    auth_verify_url="http://192.168.1.202:3306"
    sms_url = "http://ysms.game2palm.com:8899/smsAccept/sendSms.action"
    request_url = auth_verify_url+"/auth_verify/power/verify"
    # request_url = "http://127.0.0.1:2206/auth_verify/power/verify"
    db_set = {'name': 'root', 'password': 'ZTkj2018!', 'host': '192.168.1.203', 'port': '3306', 'db': 'zt_auth_online'}
    redis_set = {'host': '192.168.1.203', 'port': '6379', 'db': '8'}
    redis_access_token = {'host': '192.168.1.203', 'port': '6379', 'db': '9'}
    redis_refresh_token = {'host': '192.168.1.203', 'port': '6379', 'db': '10'}
    redis_user_info = {'host': '192.168.1.203', 'port': '6379', 'db': '11'}
elif check=='test':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=2205
    auth_verify_url = "http://192.168.1.205:2206"
    sms_url = "http://ysms.game2palm.com:8899/smsAccept/sendSms.action"
    request_url = auth_verify_url+"/auth_verify/power/verify"
    db_set = {'name': 'root', 'password': 'ZTkj2018!', 'host': '192.168.1.203', 'port': '3306', 'db': 'zt_auth'}
    redis_set = {'host': '192.168.1.203', 'port': '6379', 'db': '0'}
    redis_access_token = {'host': '192.168.1.203', 'port': '6379', 'db': '1'}
    redis_refresh_token = {'host': '192.168.1.203', 'port': '6379', 'db': '2'}
    redis_user_info = {'host': '192.168.1.203', 'port': '6379', 'db': '3'}


class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
        DEBUG = False
        SQLALCHEMY_ECHO=True
        SQLALCHEMY_POOL_SIZE=10
        SQLALCHEMY_POOL_RECYCLE = 5
        SQLALCHEMY_DATABASE_URI = "mysql://%s:%s@%s:%s/%s"%(db_set['name'],db_set['password'],db_set['host'],db_set['port'],db_set['db'])

    # MAIL_SERVER = 'email-smtp.us-west-2.amazonaws.com'
    # MAIL_PROT = 587
    # MAIL_USE_TLS = True
    # MAIL_USE_SSL = False
    # MAIL_USERNAME = "AKIAIXEVFGVWK7ILOO6A"
    # MAIL_PASSWORD = "AjAtYAjw8J5IgP8c4zckZQNDsCMhvW6gw0WkX1KjhQGV"
    # MAIL_DEBUG = True







config = {
    'default': DevelopmentConfig,
    'online':DevelopmentConfig,
    'test':DevelopmentConfig
}


