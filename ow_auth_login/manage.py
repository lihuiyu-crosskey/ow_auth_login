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
from config import blue as main_blueprint
from config import beforeLogin,server
from plugins import http_filter
import logging
import sys
from flask_sqlalchemy import SQLAlchemy
import redis
import config
from flask_mail import Mail
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
    handle = logging.FileHandler(os.path.join(os.path.dirname(__file__), 'logs/auth_login.log'))
    formatter = logging.Formatter(
        '-' * 80 + '\n' +
        '%(asctime)s %(levelname)s in %(module)s [%(pathname)s:%(lineno)d]:\n' +
        '%(message)s\n' +
        '-' * 80)
    handle.setFormatter(formatter)
    handle.setLevel(logging.DEBUG)
    return handle


@main_blueprint.before_request
def before():
    request_url = config.request_url
    url = request.base_url
    header = request.headers
    uid = ''
    body = request.get_json(silent=True)
    if body:
        uid = request.get_json().get("userId", "")
        print uid
    res = http_filter.before_request(request_url, url, uid, header)
    if str(res) == 'true':
        pass
    else:
        return res


def create_app():
    app = Flask(__name__)
    app.config.from_mapping(config.sqlalchemy_set)
    app.debug=False
    db.init_app(app)
    app.logger.addHandler(file_handle())
    # mail.init_app(app)
    reload(sys)
    CORS(app, supports_credentials=True)
    sys.setdefaultencoding('utf8')
    app.register_blueprint(main_blueprint)
    app.register_blueprint(beforeLogin)
    app.register_blueprint(server)
    return app


app = create_app()
manager = Manager(app)
migrate = Migrate(app, db)


def make_shell_context():
    return dict(app=app, db=db)
manager.add_command("shell",Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)
manager.add_command("runserver", Server('0.0.0.0', port=config.port))

if __name__ == '__main__':
    manager.run()