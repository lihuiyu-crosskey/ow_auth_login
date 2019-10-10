# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2019-7-19
Author: lihuiyu
"""
import os
from flask import Flask,request
from app import beforeLogin,server,logged
from plugins import http_filter,mydb
import logging
import redis
import config
from flask_cors import *
import json



# mail=Mail()
cur= mydb.Connection(config.db_set['host'] + ":" + config.db_set['port'], config.db_set['db'], config.db_set['name'], config.db_set['password'], 100, 10)
red = redis.StrictRedis(host=config.redis_set['host'], port=config.redis_set['port'], db=config.redis_set['db'],password=config.redis_set['password'])







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

# @beforeLogin.before_request
# def test():
#     header = request.headers
#     test=header['test']
#     tes=json.loads(test)
#     print(tes['username'])






app = Flask(__name__)
app.config.from_mapping(config.sqlalchemy_set)
app.debug=False
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




