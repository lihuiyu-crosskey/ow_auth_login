#-*- coding: UTF-8 -*-
from app.services import auth_web_ser
from flask import jsonify, request, redirect, make_response,Flask
from .. import blue
from ..Messages.mess_handler import Message
from datetime import datetime
from flask import current_app






@blue.route('/power/verify', methods=['POST'])
def power_verify():
    try:
        req=request.get_json()
        header=req["header"]
        token=header['token']
        url=req['url']
        uid=req['uid']
        data = auth_web_ser.verify_power(token,url,uid)
        return data
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/refresh_token/refresh', methods=['POST'])
def refresh_token():
    try:
        req=request.get_json()
        return auth_web_ser.refresh_token(req['refresh_token'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")




