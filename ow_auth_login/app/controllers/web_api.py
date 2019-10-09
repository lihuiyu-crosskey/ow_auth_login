#-*- coding: UTF-8 -*-
from app.services import web_ser
from flask import jsonify, request, redirect, make_response,Flask
from app import logged,beforeLogin
from ..Messages.mess_handler import Message
from datetime import datetime
from flask import current_app



@beforeLogin.route('/login', methods=['POST'],endpoint='用户登录')
def login():
    try:
        req=request.get_json()
        header=request.headers
        return web_ser.login(header['OperationPlatform'],req['mobile'],req['password'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")


@beforeLogin.route('/mobile/reg', methods=['POST'],endpoint='手机注册')
def mobile_reg():
    try:
        req=request.get_json()
        return web_ser.mobile_reg(req['password'],req['mobile'],req['nick_name'],req['user_img'],req['code'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@beforeLogin.route('/mobile/sms/send', methods=['POST'],endpoint='发送短信')
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


@beforeLogin.route('/mobile/code/get', methods=['POST'],endpoint='手机获取验证码')
def mobile_get_code():
    try:
        req=request.get_json()
        return web_ser.mobile_get_code(req['mobile'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")


@beforeLogin.route('/mobile/code/check', methods=['POST'],endpoint='校验手机验证码')
def check_mobile_code():
    try:
        req=request.get_json()
        return web_ser.check_mobile_code(req['mobile'],req['code'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")



@beforeLogin.route('/mobile/password/find', methods=['POST'],endpoint='找回密码')
def find_password():
    try:
        req=request.get_json()
        return web_ser.find_password(req['mobile'],req['password'],req['code'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")
