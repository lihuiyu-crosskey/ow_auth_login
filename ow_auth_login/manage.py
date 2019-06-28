# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2017-5-3
Author: lihuiyu
"""
import os
from flask_script import Manager, Shell,Server
from flask_migrate import Migrate, MigrateCommand
from flask import Flask,request
from app.models import db
# from app.models import mail
from config import config,port
from app import blue as main_blueprint
from app import beforeLogin,server
from plugins import http_filter
import logging
import config as configs
import sys

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
    request_url = configs.request_url
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


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    db.init_app(app)
    app.logger.addHandler(file_handle())
    # mysql.init_app(app)
    # mail.init_app(app)
    reload(sys)
    sys.setdefaultencoding('utf8')
    app.register_blueprint(main_blueprint)
    app.register_blueprint(beforeLogin)
    app.register_blueprint(server)
    return app


app = create_app(os.getenv('FLASK_CONFIG') or 'default')

manager = Manager(app)
migrate = Migrate(app, db)


def make_shell_context():
    return dict(app=app, db=db)
manager.add_command("shell",Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)
manager.add_command("runserver", Server('0.0.0.0', port=port))

if __name__ == '__main__':
    manager.run()