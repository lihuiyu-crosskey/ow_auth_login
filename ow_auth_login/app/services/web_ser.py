# -*- coding: UTF-8 -*-
from ..Errors.error_handler import ErrorHandle
from ..Messages.mess_handler import Message
from flask import jsonify
import json
from werkzeug.security import gen_salt
import base64
import hashlib
import json
import time
import ast
import config
from flask import current_app
from random import Random
import string, random
import urllib
import manage
from app.models import auth
import datetime
import re
from app.models import db




def test():
    c=manage.cur.query('select * from tab_user')
    manage.red.set('1','2')
    b=manage.red.get('1')
    d = datetime.datetime.now()
    a = auth.TabUser.query.filter().first()

    return 1



#登录操作
def login(head,mobile,password):
    try:
        sys=head['OnWheelsSystem']
        mobile=str(mobile)
        password=str(password)
        a = auth.TabUser.query.filter(auth.TabUser.mobile==mobile,auth.TabUser.status!=2).first()
        if a :
            #校验用户状态
            if int(a.status) ==1 :
                return Message.json_mess(14,"账户已经被封","")
            #密码加盐加密
            word=str(password)+a.salt
            word=hashlib.md5(word).hexdigest()
            #密码验证
            if word == a.password:
                mysys=''
                if sys=='iOSOnWheels' or sys=='androidOnWheels':
                    mysys='mobile'
                    type=1
                else:
                    mysys='web'
                    type=2

                #组合token的body
                self = {"user_id": a.id, 'role_id': a.role_id, 'nick_name': a.nick_name, 'mobile': a.mobile,
                        'status': a.status,'sys':mysys}
                #生产token
                res = token_login(dict(self),type)
                res = res.copy()
                access_token = res["access_token"]
                refresh_token = res["refresh_token"]
                expires = res["expires"]
                token = {'access_token': access_token, 'refresh_token': refresh_token, 'expires': expires}

                return Message.json_mess(0,'登陆成功',token)
            else:
                return Message.json_mess(18, '密码错误', '')
        else :
            return Message.json_mess(15,'账户不存在','')
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(12, '登录失败', '')


def mobile_get_code(mobile):
    try:
        check=check_mobile(mobile)
        if check==0:
            mobile=str(mobile)
            code=get_random_num(6)
            red_key="mobile_code_"+mobile
            manage.red.set(red_key,code)
            manage.red.expire(red_key,3600)
            msg="验证码："+str(code)+"，请于1分钟内输入。若非本人操作，请忽略！"
            ress=send_sms(mobile,msg)
            if ress==0:
                res={'mobile_code':code}
                return Message.json_mess(0,'获取手机验证码成功','')
            else:
                return Message.json_mess(21, '获取手机验证码失败', '')
        else:
            return Message.json_mess(21, '获取手机验证码失败', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(21,'获取手机验证码失败','')

def send_sms(nums,message):
    try:
        mess64= base64.b64encode(message)
        messcode=urllib.parse.quote(mess64)
        res={'sid':'710446','mobi':nums,'sign':'fc08d39e714e4355881baf769ec8b940','msg':messcode}
        rs=Message.post_json_request(config.sms_url,res,1)
        # print rs
        s=rs.split('|')
        if s[0]=='1000':
            return 0
        else:
            current_app.logger.error(rs)
            return 1

    except Exception as e:
        current_app.logger.error(str(e))
        return 1

def get_random_num(num):
    str = ""
    for i in range(num):
        ch = chr(random.randrange(ord('0'), ord('9') + 1))
        str += ch
    return str


def check_mobile(mobile):
    try:
        check=re.match(r"^1[356789]\d{9}$", mobile)
        if check:
            return 0
        else:
            return 1
    except Exception as e:
        current_app.logger.error(str(e))
        return 1


def check_mobile_code(mobile,code):
    try:
        check = check_mobile(mobile)
        if check==0:
            check_code = manage.red.get('mobile_code_' + str(mobile))
            if check_code is None:
                return Message.json_mess(22, "验证码不存在", "")
            if check_code != code:
                return Message.json_mess(23, "验证码校验失败", "")

            return Message.json_mess(0, "验证码校验成功", "")
        else:
            return Message.json_mess(23, "验证码校验失败", "")
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(23, "验证码校验失败", "")



#手机注册
def mobile_reg(password,mobile,nick_name,code,user_img):
    try:
        manage.cur.reconnect()

        #手机号查重
        check_name=auth.TabUser.query.filter(auth.TabUser.mobile==mobile,auth.TabUser.status!=2).first()
        if check_name:
            return Message.json_mess(11,"手机号重复","")

        check_code=manage.red.get('mobile_code_'+str(mobile))
        if check_code is None:
            return Message.json_mess(22, "验证码不存在", "")
        if check_code!=code:
            return Message.json_mess(23, "验证码校验失败", "")
        get_role_id=auth.TabRole.query.filter(auth.TabRole.type==1,auth.TabRole.status!=2).first()

        u=auth.TabUser()
        u.nick_name=nick_name
        word = str(password)
        #生产盐，然后将密码和盐拼接一起MD5加密存入数据库
        u.salt = gen_salt(6)
        word = word + str(u.salt)
        password_md5 = hashlib.md5(word).hexdigest()
        u.password = password_md5
        u.mobile=mobile
        u.status=0
        u.role_id=get_role_id.id
        u.is_real=0
        u.user_img=user_img
        u.create_time=datetime.now()
        manage.db.session.add(u)
        manage.db.session.commit()
        res={'user_id':u.id,'role_id':u.role_id,'status':u.status,'role_type':1}
        key="user_info_"+str(u.id)
        #将基础的用户信息存入redis
        manage.red.set(key,json.dumps(res))

        return Message.json_mess(0,'添加成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        #添加时一旦发生错误，回滚
        a=auth.TabUser.query.filter(auth.TabUser.mobile==mobile,auth.TabUser.status!=2).first()
        if a:
            a.status=2
            manage.db.session.add(a)
            manage.db.session.commit()
        return Message.json_mess(7, '添加失败', '')


def find_password(mobile,password,code):
    try:
        manage.cur.reconnect()
        check=check_mobile(mobile)
        if check==0:
            real_code=manage.red.get("mobile_code_"+str(mobile))
            if str(real_code)==str(code):
                u = auth.TabUser.query.filter(auth.TabUser.mobile == mobile, auth.TabUser.status != 2).first()
                if u:
                    word = str(password)
                    u.salt = gen_salt(6)
                    word = word + str(u.salt)
                    password_md5 = hashlib.md5(word).hexdigest()
                    u.password = password_md5
                    manage.db.session.add(u)
                    manage.db.session.commit()
                    return Message.json_mess(0, '找回成功', '')
                else:
                    return Message.json_mess(8, '用户不存在', '')
            else:
                return Message.json_mess(8, '验证码错误', '')
        else:
            return Message.json_mess(8, '找回失败', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')



#添加用户
def add_user(nick_name,password,mobile,role_id,user_img):
    try:
        manage.cur.reconnect()
        #检测添加的role_id是否非正数
        if role_id<=0:
            return Message.json_mess(13,"无此权限","")
        #昵称查重
        check_name=auth.TabUser.query.filter(auth.TabUser.nick_name==nick_name,auth.TabUser.status!=2).first()
        if check_name:
            return Message.json_mess(11,"昵称重复","")
        check_mobile=auth.TabUser.query.filter(auth.TabUser.mobile==mobile,auth.TabUser.status!=2).first()
        if check_mobile:
            return Message.json_mess(11,"手机号重复","")
        u=auth.TabUser()
        u.nick_name=nick_name
        word = str(password)
        #生产盐，然后将密码和盐拼接一起MD5加密存入数据库
        u.salt = gen_salt(6)
        word = word + str(u.salt)
        password_md5 = hashlib.md5(word).hexdigest()
        u.password = password_md5
        u.mobile=mobile
        u.status=0
        u.role_id=role_id
        u.create_time=datetime.now()
        u.user_img=user_img
        db.session.add(u)
        db.session.commit()
        res={'user_id':u.id,'role_id':u.role_id,'status':u.status,'nick_name':nick_name,'mobile':mobile,'user_img':user_img}
        key="user_info_"+str(u.id)
        #将基础的用户信息存入redis
        manage.red.set(key,json.dumps(res))

        return Message.json_mess(0,'添加成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        #添加时一旦发生错误，回滚
        a=auth.TabUser.query.filter(auth.TabUser.mobile==mobile,auth.TabUser.status!=2).first()
        if a:
            a.status=2
            db.session.add(a)
            db.session.commit()
        return Message.json_mess(7, '添加失败', '')

def add_admin_user(nick_name,password,mobile):
    try:
        manage.cur.reconnect()
        # 昵称查重
        check_name = auth.TabUser.query.filter(auth.TabUser.nick_name == nick_name, auth.TabUser.status != 2).first()
        if check_name:
            return Message.json_mess(11, "昵称重复", "")
        check_mobile = auth.TabUser.query.filter(auth.TabUser.mobile == mobile, auth.TabUser.status != 2).first()
        if check_mobile:
            return Message.json_mess(11, "手机号重复", "")
        u = auth.TabUser()
        u.nick_name = nick_name
        word = str(password)
        # 生产盐，然后将密码和盐拼接一起MD5加密存入数据库
        u.salt = gen_salt(6)
        word = word + str(u.salt)
        password_md5 = hashlib.md5(word).hexdigest()
        u.password = password_md5
        u.mobile = mobile
        u.status = 0
        u.role_id = 0
        u.create_time = datetime.now()
        db.session.add(u)
        db.session.commit()
        res = {'user_id': u.id, 'role_id': u.role_id, 'status': u.status, 'nick_name': nick_name, 'mobile': mobile}
        key = "user_info_" + str(u.id)
        # 将基础的用户信息存入redis
        manage.red.set(key, json.dumps(res))

        return Message.json_mess(0, '添加成功', '')
    except Exception as e:
        current_app.logger.error(str(e))
        # 添加时一旦发生错误，回滚
        a = auth.TabUser.query.filter(auth.TabUser.mobile == mobile, auth.TabUser.status != 2).first()
        if a:
            a.status = 2
            db.session.add(a)
            db.session.commit()
        return Message.json_mess(7, '添加失败', '')


def edit_user(id,nick_name,mobile,role_id,user_img):
    try:
        manage.cur.reconnect()
        # 检测添加的role_id是否非正数
        if role_id <= 0:
            return Message.json_mess(13, "无此权限", "")
        # 用户名查重
        check_name = auth.TabUser.query.filter(auth.TabUser.nick_name == nick_name,auth.TabUser.id!=id, auth.TabUser.status != 2).first()
        if check_name:
            return Message.json_mess(11, "昵称重复", "")
        check_mobile = auth.TabUser.query.filter(auth.TabUser.mobile == mobile, auth.TabUser.id != id,
                                               auth.TabUser.status != 2).first()
        if check_mobile:
            return Message.json_mess(11, "手机号重复", "")

        u = auth.TabUser.query.filter(auth.TabUser.id==id, auth.TabUser.status != 2).first()
        u.nick_name=nick_name
        u.mobile = mobile
        u.role_id = role_id
        u.user_img=user_img
        db.session.add(u)
        db.session.commit()
        res = {'user_id': u.id, 'role_id': u.role_id, 'status': u.status, 'nick_name': nick_name, 'mobile': mobile,
               'user_img': user_img}
        key = "user_info_" + str(u.id)
        # 将基础的用户信息存入redis
        manage.red.set(key, json.dumps(res))

        return Message.json_mess(0, '编辑成功', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')




def edit_password(id,password):
    try:
        manage.cur.reconnect()
        u = auth.TabUser.query.filter(auth.TabUser.id == id, auth.TabUser.status != 2).first()
        word = str(password)
        # 生产盐，然后将密码和盐拼接一起MD5加密存入数据库
        u.salt = gen_salt(6)
        word = word + str(u.salt)
        password_md5 = hashlib.md5(word).hexdigest()
        u.password = password_md5
        db.session.add(u)
        db.session.commit()


        return Message.json_mess(0, '编辑成功', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')

def change_password(old_password,new_password,token):
    try:
        manage.cur.reconnect()
        # 获取token的body解析出的json
        body = get_token_body(token)
        id = body['user_id']
        u = auth.TabUser.query.filter(auth.TabUser.id == id, auth.TabUser.status != 2).first()
        checkpass=str(old_password)+str(u.salt)
        checkpass=hashlib.md5(checkpass).hexdigest()
        if str(checkpass) == str(u.password):
            word = str(new_password)
            # 生产盐，然后将密码和盐拼接一起MD5加密存入数据库
            u.salt = gen_salt(6)
            word = word + str(u.salt)
            password_md5 = hashlib.md5(word).hexdigest()
            u.password = password_md5
            db.session.add(u)
            db.session.commit()
            return Message.json_mess(0, '修改成功', '')
        else:
            return Message.json_mess(18, '原始密码不正确', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '修改失败', '')


def delete_user(id):
    try:
        manage.cur.reconnect()
        u = auth.TabUser.query.filter(auth.TabUser.id==id, auth.TabUser.status != 2).first()
        u.status = 2
        db.session.add(u)
        db.session.commit()
        key = "user_info_" + str(u.id)
        # 将基础的用户信息存入redis
        manage.red.delete(key)
        return Message.json_mess(0, '删除成功', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')

def user_data(token,page_index,page_size):
    try:
        page_size=int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        body=get_token_body(token)
        role_id=body['role_id']
        if int(role_id) >=0:
            sql = "SELECT a.id,a.nick_name,mobile,role_id,case when a.role_id = 0 then '超级管理员' else b.role_name end as role_name,a.create_time,a.user_img FROM tab_user a LEFT JOIN tab_role b on a.role_id=b.id WHERE a.`status`!=2  ORDER BY a.create_time DESC LIMIT %s,%s"
            data = manage.cur.query(sql, page_index, page_size)
            sql_count = "SELECT count(1) as count FROM tab_user a LEFT JOIN tab_role b on a.role_id=b.id WHERE a.`status`!=2 "
            count = manage.cur.get(sql_count)
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}
            return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')

def user_data_single(user_id):
    try:
        sql = "select * from tab_user where id=%s"
        data = manage.cur.query(sql, user_id)
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')


#添加角色
def add_role(name):
    try:
        check_name=auth.TabRole.query.filter(auth.TabRole.role_name==name,auth.TabRole.status!=2).first()
        if check_name:
            return Message.json_mess(11,"角色名重复","")
        u=auth.TabRole()
        u.role_name=name
        u.status=0
        u.type=0
        db.session.add(u)
        db.session.commit()
        return Message.json_mess(0,'添加成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')

def edit_role(id,name):
    try:
        check_name=auth.TabRole.query.filter(auth.TabRole.role_name==name,auth.TabRole.id!=id,auth.TabRole.status!=2).first()
        if check_name:
            return Message.json_mess(11,"角色名重复","")
        u=auth.TabRole.query.filter(auth.TabRole.id==id,auth.TabRole.status!=2).first()
        u.role_name=name
        db.session.add(u)
        db.session.commit()
        return Message.json_mess(0,'编辑成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')

def delete_role(id):
    try:
        manage.cur.reconnect()
        u=auth.TabRole.query.filter(auth.TabRole.id==id,auth.TabRole.status!=2).first()
        u.status=2
        db.session.add(u)
        db.session.commit()
        sql = "delete from tab_role_power_group where role_id=" + str(id)
        manage.cur.execute(sql)

        return Message.json_mess(0,'删除成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')
    finally:
        manage.cur.close()

def role_data(page_index,page_size):
    try:
        manage.cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        sql = "select * from tab_role where status!=2 limit %s,%s"
        data = manage.cur.query(sql, page_index, int(page_size))
        sql_count = "select count(1) as count from tab_role where status!=2"
        count = manage.cur.get(sql_count)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, "查询失败", "")
    finally:
        manage.cur.close()


def add_power(name,url,type):
    try:
        check_name=auth.TabPower.query.filter(auth.TabPower.power_name==name).first()
        if check_name:
            return Message.json_mess(11,"权限名重复","")
        check_url = auth.TabPower.query.filter(auth.TabPower.power_url == url).first()
        if check_url:
            return Message.json_mess(11, "权限码重复", "")
        u=auth.TabPower()
        u.power_name=name
        u.power_url = url
        u.type=int(type)
        db.session.add(u)
        db.session.commit()

        return Message.json_mess(0,'添加成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')



def delete_power(id):
    try:
        u=auth.TabPower.query.filter(auth.TabPower.id==id).first()
        db.session.delete(u)
        db.session.commit()
        res = { 'power_url': u.power_url, 'power_name': u.power_name, 'power_type': u.type,'power_id': u.id}
        sql= "select role_id from tab_role_power where power_id=%s"
        data=manage.cur.query(sql,id)
        if data:
            a=1
            # for role_id in data:
            #     key="role_"+str(role_id['role_id'])
            #     red_user_info.srem(key,json.dumps(res))
        # sql = "delete from tab_role_power where power_id=%s"
        # cur.execute(sql,id)
        # sql = "delete from tab_menu_power where power_id=%s"
        # cur.execute(sql, id)

        return Message.json_mess(0,'删除成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')


def power_data(type,page_index,page_size):
    try:
        manage.cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        if int(type) >0:
            sql = """select * from tab_power where type=%s order by type asc,id desc limit %s,%s """
            data = manage.cur.query(sql,int(type), page_index, page_size)
            sql_count = "select count(*) as count from tab_power where type=%s"
            count = manage.cur.get(sql_count,int(type))
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}
        elif int(type)==0:
            sql = """select * from tab_power order by type asc,id desc limit %s,%s """
            data = manage.cur.query(sql, page_index, page_size)
            sql_count = "select count(*) as count from tab_power "
            count = manage.cur.get(sql_count)
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, "查询失败", "")
    finally:
        manage.cur.close()

def add_power_group(name):
    try:
        check_name=auth.TabPowerGroup.query.filter(auth.TabPowerGroup.name==name).first()
        if check_name:
            return Message.json_mess(11,"权限组名称重复","")
        u=auth.TabPowerGroup()
        u.name=name
        db.session.add(u)
        db.session.commit()
        return Message.json_mess(0,'添加成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')

def edit_power_group(id,name):
    try:
        check_name=auth.TabPowerGroup.query.filter(auth.TabPowerGroup.name==name,auth.TabPowerGroup.id!=id).first()
        if check_name:
            return Message.json_mess(11,"权限组名称重复","")
        u=auth.TabPowerGroup.query.filter(auth.TabPowerGroup.id==id).first()
        u.name=name
        db.session.add(u)
        db.session.commit()
        return Message.json_mess(0,'编辑成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')

def delete_power_group(id):
    try:
        manage.cur.reconnect()
        u=auth.TabPowerGroup.query.filter(auth.TabPowerGroup.id==id).first()
        db.session.delete(u)
        db.session.commit()
        sql="delete from tab_power_power_group where power_group_id="+str(id)
        manage.cur.execute(sql)

        return Message.json_mess(0,'删除成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')
    finally:
        manage.cur.close()

def power_group_data(page_index,page_size):
    try:
        manage.cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        sql = "select * from tab_power_group order by id desc limit %s,%s"
        data = manage.cur.query(sql, page_index, page_size)
        sql_count = "select count(*) as count from tab_power_group"
        count = manage.cur.get(sql_count)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, "查询失败", "")
    finally:
        manage.cur.close()





















def get_token_body(token):
    token = str(token)
    token = token.split('.')
    payload = token[1]
    payload_d = decode_token_bytes(payload)
    data = json.loads(payload_d.decode("utf8"))
    return data



def token_login(data,type):
    try:
        a=gen_token(0,data,config.access_token_expire)
        b=gen_token(1,data,config.refresh_token_expire)
        a=a.copy()
        b=b.copy()
        data=data.copy()
        user_id=a["user_id"]
        access_token=a["token"]
        refresh_token=b["token"]
        expires=a["expires"]
        access_key=a["key"]
        access_salt=a["salt"]
        refresh_key=b["key"]
        refresh_salt=b["salt"]
        info={"user_id":user_id,"access_token":access_token,"access_key":access_key,"access_salt":access_salt,"expires":expires,"refresh_token":refresh_token,"refresh_key":refresh_key,"refresh_salt":refresh_salt}
        info=str(info)
        if int(user_id)>0:
            manage.red.set('user_login_info_'+str(user_id),info)
            if type==1:
                manage.red.set('mobile_access_'+str(user_id),access_token)
                manage.red.expire('mobile_access_'+str(user_id),config.access_token_expire)
                manage.red.set('mobile_refresh_' + str(user_id), refresh_token)
                manage.red.expire('mobile_refresh_' + str(user_id), config.refresh_token_expire)
            elif type==2:
                manage.red.set('web_access_' + str(user_id), access_token)
                manage.red.expire('web_access_' + str(user_id), config.access_token_expire)
                manage.red.set('web_refresh_' + str(user_id), refresh_token)
                manage.red.expire('web_refresh_' + str(user_id), config.refresh_token_expire)

        res={"access_token":access_token,"refresh_token":refresh_token,"expires":expires}
        return res
    except Exception as e:
        current_app.logger.error(str(e))
        return {}









# token生成器
def gen_token(type,data,TIMEOUT):
    '''
    :param data: dict type
    :return: base64 str
    '''
    try:
        if int(type)== 0:
            type="access"
        elif int(type)==1:
            type="refresh"
        header={"typ":"JWT","token_type":type}
        header=encode_token_bytes(str(header))
        # print "header:"+header
        data = data.copy()
        user_id=data["user_id"]
        if "expires" not in data:
            expires= time.time() + TIMEOUT
            data["expires"] = expires
            # print "expires:"+str(expires)
        payload = json.dumps(data).encode("utf8")
        # 生成签名
        payload=encode_token_bytes(payload)
        # print "payload:"+payload

        s_key=gen_salt(6)
        s_salt=gen_salt(6)
        # print "key:"+s_key
        # print "salt:"+s_salt
        signer=_get_signature(header+payload+s_salt+s_key)

        # print "sign:"+signer
        token=header+"."+payload+"."+signer
        # print "token:"+token
        info={"user_id":user_id,"token":token,"key":s_key,"salt":s_salt,"expires":expires}
        # info=str(info)
        return info
    except Exception as e:
        current_app.logger.error(str(e))
        return {}


# 加密
def _get_signature(value):
    """Calculate the HMAC signature for the given value."""
    mySha = hashlib.sha256()
    mySha.update(value)
    # print mySha.hexdigest()
    return mySha.hexdigest()

# 下面两个函数将base64编码和解码单独封装
def encode_token_bytes(data):
    return base64.urlsafe_b64encode(data)

def decode_token_bytes(data):
    return base64.urlsafe_b64decode(data)




# def random_str(randomlength):
#     str = ''
#     chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
#     length = len(chars) - 1
#     random = Random()
#     for i in range(randomlength):
#         str+=chars[random.randint(0, length)]
#
#     check=red_username_set.sismember("username",str)
#     if check:
#         random_str(randomlength)
#     else:
#         red_username_set.sadd("username",str)
#     return str


fontPath = "/usr/share/fonts/truetype/ttf-devanagari-fonts/"

# 获得随机四个字母
def getRandomChar():
    return [random.choice(string.letters) for _ in range(4)]




