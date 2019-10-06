#-*- coding: UTF-8 -*-
from app.services import web_ser
from flask import jsonify, request, redirect, make_response,Flask,url_for
from app import blue,beforeLogin
from ..Messages.mess_handler import Message
from datetime import datetime
from flask import current_app



@beforeLogin.route('/test/test', methods=['POST'])
def get_username_by_ids():
    try:
        req=request.get_json()
        return Message.json_mess(0,"测试成功",req)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")



@beforeLogin.route('/url/get', methods=['POST'])
def get_url():
    try:
        req=url_for("beforeLogin.get_username_by_ids")
        return Message.json_mess(0,"测试成功",req)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

