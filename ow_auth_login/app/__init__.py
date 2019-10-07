# -*- coding:utf-8 -*-
from flask import Blueprint
logged = Blueprint('controllers', __name__)
beforeLogin=Blueprint('beforeLogin', __name__)
server=Blueprint('server', __name__)

from app.controllers import web_api,server_api
# from app.Errors import error_handler
from app.Messages import mess_handler