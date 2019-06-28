# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2017-5-3
Author: QL Liu
"""
from flask import Blueprint
blue = Blueprint('controllers', __name__,url_prefix='/auth_login')
beforeLogin=Blueprint('beforeLogin', __name__,url_prefix='/auth_login')
server=Blueprint('server', __name__,url_prefix='/auth_login')

from app.controllers import auth_web,auth_server
from app.Errors import error_handler
from app.Messages import mess_handler