# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2019-7-19
Author: lihuiyu
"""
import os
from flask_script import Manager, Shell,Server
from flask_migrate import Migrate, MigrateCommand
from flask import Flask,request
from app import beforeLogin,server,logged
from plugins import http_filter
import logging
import sys
from flask_sqlalchemy import SQLAlchemy
import redis
import config
import torndb
from flask_cors import *


db = SQLAlchemy()

# mail=Mail()

red = redis.StrictRedis(host=config.redis_set['host'], port=config.redis_set['port'], db=config.redis_set['db'])
red_access_token = redis.StrictRedis(host=config.redis_access_token['host'], port=config.redis_access_token['port'], db=config.redis_access_token['db'])
red_refresh_token = redis.StrictRedis(host=config.redis_refresh_token['host'], port=config.redis_refresh_token['port'], db=config.redis_refresh_token['db'])
red_user_info = redis.StrictRedis(host=config.redis_user_info['host'], port=config.redis_user_info['port'], db=config.redis_user_info['db'])

cur=torndb.Connection(config.db_set['host']+":"+config.db_set['port'],config.db_set['db'],config.db_set['name'],config.db_set['password'],100,10)




def file_handle():
    """
    生成一个log handler 用于将日志记录到文件中
    :return:
    """
    handle = logging.FileHandler(os.path.join(os.path.dirname(__file__), 'logs/bug_log.log'))
    formatter = logging.Formatter(
        '-' * 80 + '\n' +
        '%(asctime)s %(levelname)s in %(module)s [%(pathname)s:%(lineno)d]:\n' +
        '%(message)s\n' +
        '-' * 80)
    handle.setFormatter(formatter)
    handle.setLevel(logging.DEBUG)
    return handle


@logged.before_request
def before():
    request_url = config.request_url
    url = request.base_url
    header = request.headers
    uid = ''
    body = request.get_json(silent=True)
    if body:
        uid = request.get_json().get("userId", "")
        print (uid)
    res = http_filter.before_request(request_url, url, uid, header)
    if str(res) == 'true':
        pass
    else:
        return res



app = Flask(__name__)
app.config.from_mapping(config.sqlalchemy_set)
app.debug=False
db.init_app(app)
app.logger.addHandler(file_handle())
CORS(app, supports_credentials=True)
app.register_blueprint(logged)
app.register_blueprint(beforeLogin)
app.register_blueprint(server)
for i,val in enumerate(app.url_map._rules):
    # print(i)
    print(val)
    # print(val.endpoint)
    test=str(val.endpoint).split('.')
    if len(test)>1:

        print(test[1])



