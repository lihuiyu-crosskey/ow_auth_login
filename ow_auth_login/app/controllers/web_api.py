#-*- coding: UTF-8 -*-
from app.services import web_ser
from flask import jsonify, request, redirect, make_response,Flask
from app import logged,beforeLogin
from ..Messages.mess_handler import Message
from datetime import datetime
from flask import current_app


@beforeLogin.route('/mytest', methods=['POST'])
def myts():
    try:
        req=request.get_json()
        header=request.headers
        return web_ser.test()
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")



