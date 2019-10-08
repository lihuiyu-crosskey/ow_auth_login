#-*- coding: UTF-8 -*-
from app.services import web_ser
from flask import jsonify, request, redirect, make_response,Flask
from app import blue,beforeLogin
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


@beforeLogin.route('/login', methods=['POST'])
def login():
    try:
        req=request.get_json()
        header=request.headers
        return web_ser.login(header,req['username'],req['password'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@beforeLogin.route('/mobile/reg', methods=['POST'])
def mobile_reg():
    try:
        req=request.get_json()
        return web_ser.mobile_reg(req['password'],req['mobile'],req['nick_name'],req['code'],req['user_img'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@beforeLogin.route('/mobile/sms/send', methods=['POST'])
def send_sms():
    try:
        req=request.get_json()
        res= web_ser.send_sms(req['nums'],req['message'])
        if res==0:
            return Message.json_mess(0, "发送成功", "")
        else:
            return Message.json_mess(25, "短信发送失败", "")
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")


@beforeLogin.route('/mobile/code/get', methods=['POST'])
def mobile_get_code():
    try:
        req=request.get_json()
        return web_ser.mobile_get_code(req['mobile'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")


@beforeLogin.route('/mobile/code/check', methods=['POST'])
def check_mobile_code():
    try:
        req=request.get_json()
        return web_ser.check_mobile_code(req['mobile'],req['code'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@beforeLogin.route('/mobile/password/find', methods=['POST'])
def find_password():
    try:
        req=request.get_json()
        return web_ser.find_password(req['mobile'],req['passwords'],req['code'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")




