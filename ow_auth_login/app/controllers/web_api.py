#-*- coding: UTF-8 -*-
from app.services import web_ser
from flask import request
from app import logged,beforeLogin
from ..Messages.mess_handler import Message
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


@beforeLogin.route('/access_token/get', methods=['POST'],endpoint='用refresh_token换取access_token')
def refresh_token():
    try:
        req=request.get_json()
        return web_ser.refresh_token(req['refresh_token'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@logged.route('/user/add', methods=['POST'],endpoint='添加用户')
def add_user():
    try:
        req=request.get_json()
        return web_ser.add_user(req['password'],req['mobile'],req['nick_name'],req['user_img'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@logged.route('/user/edit', methods=['POST'],endpoint='编辑用户')
def edit_user():
    try:
        req=request.get_json()
        return web_ser.edit_user(req['user_id'],req['mobile'],req['nick_name'],req['user_img'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@logged.route('/user/delete', methods=['POST'],endpoint='删除用户')
def delete_user():
    try:
        req=request.get_json()
        return web_ser.delete_user(req['user_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@logged.route('/user/password/force/change', methods=['POST'],endpoint='强制修改密码')
def force_change_password():
    try:
        req=request.get_json()
        return web_ser.force_change_password(req['user_id'],req['password'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@logged.route('/user/password/change', methods=['POST'],endpoint='修改密码')
def change_password():
    try:
        req=request.get_json()
        header=request.headers
        return web_ser.change_password(req['old_password'],req['new_password'],header['access_token'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

