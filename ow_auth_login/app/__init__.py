# -*- coding:utf-8 -*-
from flask import Blueprint
blue = Blueprint('controllers', __name__,url_prefix='/auth_login')
beforeLogin=Blueprint('beforeLogin', __name__,url_prefix='/auth_login')
server=Blueprint('server', __name__,url_prefix='/auth_login')


from app.controllers import web_api,server_api
from app.Messages import mess_handler