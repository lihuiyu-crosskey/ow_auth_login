#-*- coding: UTF-8 -*-
from app.services import auth_web_ser
from flask import jsonify, request, redirect, make_response,Flask
from .. import blue,beforeLogin
from ..Messages.mess_handler import Message
from datetime import datetime
from flask import current_app




@beforeLogin.route('/login', methods=['POST'])
def login():
    try:
        req=request.get_json()
        return auth_web_ser.login(req['username'],req['passwords'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@beforeLogin.route('/mobile/reg', methods=['POST'])
def mobile_reg():
    try:
        req=request.get_json()
        return auth_web_ser.mobile_reg(req['passwords'],req['mobile'],req['code'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@beforeLogin.route('/mobile/sms/send', methods=['POST'])
def send_sms():
    try:
        req=request.get_json()
        res= auth_web_ser.send_sms(req['nums'],req['message'])
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
        return auth_web_ser.mobile_get_code(req['mobile'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@beforeLogin.route('/login/menu/load', methods=['POST'])
def menu_load():
    try:
        header = request.headers
        return auth_web_ser.menu_load(header['access_token'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")


@blue.route('/login/user/add', methods=['POST'])
def add_user():
    try:
        req=request.get_json()
        header = request.headers
        return auth_web_ser.add_user(req['username'],req['real_name'],req['passwords'],req['mobile'],req['role_id'],header['access_token'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")


@blue.route('/login/user/edit', methods=['POST'])
def edit_user():
    req=request.get_json()
    header = request.headers
    return auth_web_ser.edit_user(req['user_id'],req['username'],req['real_name'],req['mobile'],req['role_id'],header['access_token'])

@blue.route('/login/user/password/edit', methods=['POST'])
def edit_user_password():
    req=request.get_json()
    header = request.headers
    return auth_web_ser.edit_password(req['user_id'],req['passwords'],header['access_token'])

@blue.route('/login/user/password/change', methods=['POST'])
def change_user_password():
    req=request.get_json()
    header = request.headers
    return auth_web_ser.change_password(req['old_password'],req['new_password'],header['access_token'])

@blue.route('/login/user/delete', methods=['POST'])
def delete_user():
    req=request.get_json()
    header = request.headers
    return auth_web_ser.delete_user(req['user_id'],header['access_token'])

@blue.route('/login/user/data', methods=['POST'])
def user_data():
    try:
        req=request.get_json()
        header = request.headers
        return auth_web_ser.user_data(header['access_token'],req['page_index'],req['page_size'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")

@blue.route('/login/user/single/data', methods=['POST'])
def user_data_single():
    try:
        req=request.get_json()
        header = request.headers
        return auth_web_ser.user_data_single(req['user_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")


@blue.route('/login/role/add', methods=['POST'])
def add_role():
    try:
        req=request.get_json()
        return auth_web_ser.add_role(req['role_name'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/role/edit', methods=['POST'])
def edit_role():
    try:
        req=request.get_json()
        return auth_web_ser.edit_role(req['role_id'],req['role_name'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/role/delete', methods=['POST'])
def delete_role():
    try:
        req=request.get_json()
        return auth_web_ser.delete_role(req['role_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/role/data', methods=['POST'])
def role_data():
    try:
        req=request.get_json()
        return auth_web_ser.role_data(req['page_index'],req['page_size'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/power/add', methods=['POST'])
def add_power():
    try:
        req=request.get_json()
        return auth_web_ser.add_power(req['power_name'],req['power_url'],req['type'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/power/delete', methods=['POST'])
def delete_power():
    try:
        req=request.get_json()
        return auth_web_ser.delete_power(req['power_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/power/data', methods=['POST'])
def power_data():
    try:
        req=request.get_json()
        return auth_web_ser.power_data(req['type'],req['page_index'],req['page_size'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/role/power/add', methods=['POST'])
def add_role_power():
    try:
        req=request.get_json()
        return auth_web_ser.add_role_power(req['role_id'],req['power_ids'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/roles/power/add', methods=['POST'])
def add_roles_power():
    try:
        req=request.get_json()
        return auth_web_ser.add_role_powers(req['role_ids'],req['power_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/role/power/single/add', methods=['POST'])
def add_role_power_single():
    try:
        req=request.get_json()
        return auth_web_ser.add_role_power_single(req['role_id'],req['power_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/role/device/delete', methods=['POST'])
def delete_device():
    try:
        req=request.get_json()
        header = request.headers
        return auth_web_ser.delete_device(header['access_token'],req['device_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/role/power/delete', methods=['POST'])
def delete_role_power():
    try:
        req=request.get_json()
        return auth_web_ser.delete_role_power(req['role_id'],req['power_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/role/power/data', methods=['POST'])
def role_power_data():
    try:
        req=request.get_json()
        return auth_web_ser.role_power_data(req['role_id'],req['page_index'],req['page_size'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/device/role/data', methods=['POST'])
def device_role_data():
    try:
        req=request.get_json()
        return auth_web_ser.device_role_data(req['device_id'],req['page_index'],req['page_size'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/menu/add', methods=['POST'])
def add_menu():
    try:
        req=request.get_json()
        return auth_web_ser.add_menu(req['menu_name'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/menu/edit', methods=['POST'])
def edit_menu():
    try:
        req=request.get_json()
        return auth_web_ser.edit_menu(req['menu_id'],req['menu_name'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/menu/delete', methods=['POST'])
def delete_menu():
    try:
        req=request.get_json()
        return auth_web_ser.delete_menu(req['menu_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/menu/data', methods=['POST'])
def menu_data():
    try:
        req=request.get_json()
        return auth_web_ser.menu_data(req['page_index'],req['page_size'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/menu/power/add', methods=['POST'])
def add_menu_power():
    try:
        req=request.get_json()
        return auth_web_ser.add_menu_power(req['menu_id'],req['power_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/menu/power/delete', methods=['POST'])
def delete_menu_power():
    try:
        req=request.get_json()
        return auth_web_ser.delete_menu_power(req['menu_id'],req['power_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/menu/power/data', methods=['POST'])
def menu_power_data():
    try:
        req=request.get_json()
        return auth_web_ser.menu_power_data(req['menu_id'],req['page_index'],req['page_size'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/log/data', methods=['POST'])
def log_data():
    try:
        req=request.get_json()
        return auth_web_ser.log_data(req['user_id'],req['role_id'],req['start_time'],req['end_time'],req['type'],req['page_index'],req['page_size'],req['power_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")



@blue.route('/login/interface_category/add', methods=['POST'])
def add_interface_category():
    try:
        req=request.get_json()
        return auth_web_ser.add_interface_category(req['interface_category_name'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/interface_category/edit', methods=['POST'])
def edit_interface_category():
    try:
        req=request.get_json()
        return auth_web_ser.edit_interface_category(req['interface_category_id'],req['interface_category_name'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/interface_category/delete', methods=['POST'])
def delete_interface_category():
    try:
        req=request.get_json()
        return auth_web_ser.delete_interface_category(req['interface_category_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/interface_category/data', methods=['POST'])
def interface_category_data():
    try:
        req=request.get_json()
        return auth_web_ser.interface_category_data(req['page_index'],req['page_size'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/interface_category/power/add', methods=['POST'])
def add_interface_category_power():
    try:
        req=request.get_json()
        return auth_web_ser.add_interface_category_power(req['interface_category_id'],req['power_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/interface_categorys/powers/add', methods=['POST'])
def add_interface_category_powers():
    try:
        req=request.get_json()
        return auth_web_ser.add_interface_category_powers(req['list'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


@blue.route('/login/interface_category/power/delete', methods=['POST'])
def delete_interface_category_power():
    try:
        req=request.get_json()
        return auth_web_ser.delete_interface_category_power(req['interface_category_id'],req['power_id'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@blue.route('/login/interface_category/power/data', methods=['POST'])
def interface_category_power_data():
    try:
        req=request.get_json()
        return auth_web_ser.interface_category_power_data(req['interface_category_id'],req['page_index'],req['page_size'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")
