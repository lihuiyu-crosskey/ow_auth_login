#-*- coding: UTF-8 -*-
from app.services import auth_web_ser,auth_server_ser
from flask import jsonify, request, redirect, make_response,Flask
from config import server
from ..Messages.mess_handler import Message
from datetime import datetime
from flask import current_app


@server.route('/username/by/id', methods=['POST'])
def get_username_by_id():
    try:
        req=request.get_json()
        return auth_server_ser.get_username_by_id(req['ids'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")


@server.route('/server/power/add', methods=['POST'])
def add_power():
    try:
        req = request.get_json()
        return auth_server_ser.add_power(req['name'],req['url'],req['type'],req['role_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@server.route('/server/power/delete/by/url/type', methods=['POST'])
def delete_power_by_url_type():
    try:
        req = request.get_json()
        return auth_server_ser.delete_power_by_url_type(req['url'],req['type'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@server.route('/server/power/name/edit/by/url/type', methods=['POST'])
def edit_power_name_by_url_type():
    try:
        req = request.get_json()
        return auth_server_ser.edit_pwoer_name_by_url_type(req['name'],req['url'],req['type'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@server.route('/server/role/power/add', methods=['POST'])
def add_role_power():
    try:
        req=request.get_json()
        return auth_web_ser.add_role_power(req['role_id'],req['power_ids'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@server.route('/server/role/device/add', methods=['POST'])
def add_role_device():
    try:
        req = request.get_json()
        return auth_server_ser.add_device(req['role_id'], req['device_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

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