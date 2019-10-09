#-*- coding: UTF-8 -*-
from app.services import web_ser,server_ser
from flask import jsonify, request, redirect, make_response,Flask
from app import server
from ..Messages.mess_handler import Message
from datetime import datetime
from flask import current_app




# 添加超级管理员时候用
# @server.route('/server/admin/user/add', methods=['POST'])
# def add_admin_user():
#     try:
#         req=request.get_json()
#         # name, real_name, password, mobile
#         return auth_web_ser.add_admin_user(req['name'],req['real_name'],req['password'],req['mobile'])
#     except Exception as e:
#         current_app.logger.error(e)
#         return Message.json_mess(400,"参数错误","")