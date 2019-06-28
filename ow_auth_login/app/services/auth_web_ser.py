# -*- coding: UTF-8 -*-
from app.models import cur,auth,db,red,red_access_token,red_refresh_token,red_user_info
from ..Errors.error_handler import ErrorHandle
from ..Messages.mess_handler import Message
from flask import jsonify
import json
from werkzeug.security import gen_salt
from datetime import datetime
import base64
import hashlib
import json
import time
import ast
import config
from datetime import datetime
from flask import current_app
from random import Random
import string, random
from urllib import quote,unquote



#登录操作
def login(name,password):
    try:
        name=str(name)
        password=str(password)
        a = auth.TabUser.query.filter(auth.TabUser.name==name,auth.TabUser.status!=2).first()
        if a :
            #校验用户状态
            if int(a.status) ==1 :
                return Message.json_mess(14,"账户已经被封","")
            #密码加盐加密
            word=str(password)+a.salt
            word=hashlib.md5(word).hexdigest()
            #密码验证
            if word == a.password:
                #组合token的body
                self = {"user_id": a.id, 'role_id': a.role_id, 'userName': a.name, 'mobile': a.mobile,
                        'status': a.status}
                other = {}
                self = dict(self, **other)
                #生产token
                res = token_login(dict(self))
                res = res.copy()
                access_token = res["access_token"]
                refresh_token = res["refresh_token"]
                expires = res["expires"]
                token = { 'access_token': access_token, 'refresh_token': refresh_token, 'expires': expires,'user_id':a.id,'username':a.name,'real_name':a.real_name}
                log=auth.TabLog()
                log.user_id=a.id
                log.url="login"
                log.type=1
                log.create_time=datetime.now()
                db.session.add(log)
                db.session.commit()
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

        mobile=str(mobile)
        code=get_random_num(6)
        red_key="mobile_"+mobile
        red.set(red_key,code)
        red.expire(red_key,3600)
        res={'mobile_code':code}
        return Message.json_mess(0,'获取手机验证码成功',res)
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(21,'获取手机验证码失败','')

def send_sms(nums,message):
    try:
        mess64= base64.b64encode(message)
        messcode=quote(mess64)
        res={'sid':'710446','mobi':nums,'sign':'fc08d39e714e4355881baf769ec8b940','msg':messcode}
        rs=Message.post_json_request(config.sms_url,res,1)
        print rs
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

#手机注册
def mobile_reg(password,mobile,code):
    try:
        cur.reconnect()

        #手机号查重
        check_name=auth.TabUser.query.filter(auth.TabUser.mobile==mobile,auth.TabUser.status!=2).first()
        if check_name:
            return Message.json_mess(11,"手机号重复","")

        check_code=red.get('mobile_'+str(mobile))
        if check_code is None:
            return Message.json_mess(22, "验证码不存在", "")
        if check_code!=code:
            return Message.json_mess(23, "验证码校验失败", "")
        get_role_id=auth.TabRole.query.filter(auth.TabRole.type==1,auth.TabUser.status!=2).first()

        u=auth.TabUser()
        u.name=mobile
        u.real_name=mobile
        word = str(password)
        #生产盐，然后将密码和盐拼接一起MD5加密存入数据库
        u.salt = gen_salt(6)
        word = word + str(u.salt)
        password_md5 = hashlib.md5(word).hexdigest()
        u.password = password_md5
        u.mobile=mobile
        u.is_mobile=0
        u.status=0
        u.role_id=get_role_id.id
        u.create_time=datetime.now()
        db.session.add(u)
        db.session.commit()
        res={'user_id':u.id,'role_id':u.role_id,'status':u.status}
        key="user_"+str(u.id)
        #将基础的用户信息存入redis
        red_user_info.set(key,json.dumps(res))

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


def menu_load(token):
    try:
        cur.reconnect()
        body = get_token_body(token)
        role_id = body['role_id']
        if int(role_id) >0 :
            sql="""SELECT DISTINCT a.menu_id,b.name as menu_name FROM tab_menu_power a 
LEFT JOIN tab_menu b ON a.menu_id=b.id
LEFT JOIN tab_power c on a.power_id=c.id
LEFT JOIN tab_role_power d on d.power_id=c.id
WHERE d.role_id=%s AND c.type=2"""
            menu_data=cur.query(sql,role_id)
            all_list=[]
            for menu in menu_data:
                sql="""SELECT a.power_id,c.power_name,c.power_url,c.type as power_type FROM tab_menu_power a 
LEFT JOIN tab_menu b ON a.menu_id=b.id
LEFT JOIN tab_power c on a.power_id=c.id
LEFT JOIN tab_role_power d on d.power_id=c.id
WHERE d.role_id=%s AND a.menu_id=%s AND c.type=2"""
                power_data=cur.query(sql,role_id,menu['menu_id'])
                list = []
                for power in power_data:
                    list.append(power)
                res={"menu_id":menu['menu_id'],"menu_name":menu['menu_name'],"kid":list}
                all_list.append(res)
        elif int(role_id)==0:
            sql = """SELECT DISTINCT a.menu_id,b.name as menu_name FROM tab_menu_power a
LEFT JOIN tab_menu b ON a.menu_id=b.id
LEFT JOIN tab_power c on a.power_id=c.id"""
            menu_data = cur.query(sql)
            all_list = []
            for menu in menu_data:
                sql = """SELECT a.power_id,c.power_name,c.power_url,c.type as power_type FROM tab_menu_power a
LEFT JOIN tab_menu b ON a.menu_id=b.id
LEFT JOIN tab_power c on a.power_id=c.id
WHERE a.menu_id=%s"""
                power_data = cur.query(sql,menu['menu_id'])
                list = []
                for power in power_data:
                    list.append(power)
                res = {"menu_id": menu['menu_id'], "menu_name": menu['menu_name'], "kid": list}
                all_list.append(res)

        return Message.json_mess(0,"查询成功",all_list)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, '查询失败', '')
    finally:
        cur.close()




#添加用户
def add_user(name,real_name,password,mobile,role_id,token):
    try:
        cur.reconnect()
        #检测添加的role_id是否非正数
        if role_id<=0:
            return Message.json_mess(13,"无此权限","")
        #用户名查重
        check_name=auth.TabUser.query.filter(auth.TabUser.name==name,auth.TabUser.status!=2).first()
        if check_name:
            return Message.json_mess(11,"用户账号重复","")
        #获取token的body解析出的json
        body=get_token_body(token)
        add_role_id=body['role_id']
        #检查调用接口的角色是否有权限
#         if add_role_id>0:
#             sql="""SELECT * FROM tab_role_power a
# LEFT JOIN tab_power b on a.power_id=b.id
# where a.role_id=%s and b.type=3"""
#             check=cur.query(sql,add_role_id)
#             checks=cur.query(sql,role_id)
#             #被添加的角色不能拥有多个部门权限
#             if len(checks) >1:
#                 return Message.json_mess(13, "无此权限", "")
#             #查询两个权限数组的交集，如果存在交集，则通过
#             # allcheck=list(set(check).intersection(set(checks)))
#
#             for i in check:
#                 for j in checks:
#                     if str(i['power_url'])==str(j['power_url']):
#                         pass
#                     else:
#                         return Message.json_mess(13, "无此权限", "")



        u=auth.TabUser()
        u.name=name
        u.real_name=real_name
        word = str(password)
        #生产盐，然后将密码和盐拼接一起MD5加密存入数据库
        u.salt = gen_salt(6)
        word = word + str(u.salt)
        password_md5 = hashlib.md5(word).hexdigest()
        u.password = password_md5
        u.mobile=mobile
        u.is_mobile=0
        u.status=0
        u.role_id=role_id
        u.create_time=datetime.now()
        db.session.add(u)
        db.session.commit()
        res={'user_id':u.id,'role_id':u.role_id,'status':u.status}
        key="user_"+str(u.id)
        #将基础的用户信息存入redis
        red_user_info.set(key,json.dumps(res))

        return Message.json_mess(0,'添加成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        #添加时一旦发生错误，回滚
        a=auth.TabUser.query.filter(auth.TabUser.name==name,auth.TabUser.status!=2).first()
        if a:
            a.status=2
            db.session.add(a)
            db.session.commit()
        return Message.json_mess(7, '添加失败', '')

def add_admin_user(name,real_name,password,mobile):
    try:
        cur.reconnect()
        # 用户名查重
        check_name = auth.TabUser.query.filter(auth.TabUser.name == name, auth.TabUser.status != 2).first()
        if check_name:
            return Message.json_mess(11, "用户账号重复", "")
        u = auth.TabUser()
        u.name = name
        u.real_name = real_name
        word = str(password)
        # 生产盐，然后将密码和盐拼接一起MD5加密存入数据库
        u.salt = gen_salt(6)
        word = word + str(u.salt)
        password_md5 = hashlib.md5(word).hexdigest()
        u.password = password_md5
        u.mobile = mobile
        u.is_mobile = 0
        u.status = 0
        u.role_id = 0
        u.create_time = datetime.now()
        db.session.add(u)
        db.session.commit()
        res = {'user_id': u.id, 'role_id': u.role_id, 'status': u.status}
        key = "user_" + str(u.id)
        # 将基础的用户信息存入redis
        red_user_info.set(key, json.dumps(res))
        return Message.json_mess(0, '添加成功', '')
    except Exception as e:
        current_app.logger.error(str(e))
        # 添加时一旦发生错误，回滚
        a = auth.TabUser.query.filter(auth.TabUser.name == name, auth.TabUser.status != 2).first()
        if a:
            a.status = 2
            db.session.add(a)
            db.session.commit()
        return Message.json_mess(7, '添加失败', '')


def edit_user(id,name,real_name,mobile,role_id,token):
    try:
        cur.reconnect()
        # 检测添加的role_id是否非正数
        if role_id <= 0:
            return Message.json_mess(13, "无此权限", "")
        # 用户名查重
        check_name = auth.TabUser.query.filter(auth.TabUser.name == name,auth.TabUser.id!=id, auth.TabUser.status != 2).first()
        if check_name:
            return Message.json_mess(11, "用户账号重复", "")
        # 获取token的body解析出的json
        body = get_token_body(token)
        add_role_id = body['role_id']
        # 检查调用接口的角色是否有权限
    #     if add_role_id > 0:
    #         sql = """SELECT * FROM tab_role_power a
    # LEFT JOIN tab_power b on a.power_id=b.id
    # where a.role_id=%s and b.type=3"""
    #         check = cur.query(sql, add_role_id)
    #         checks = cur.query(sql, role_id)
    #         # 被添加的角色不能拥有多个部门权限
    #         if len(checks) > 1:
    #             return Message.json_mess(13, "无此权限", "")
    #         # 查询两个权限数组的交集，如果存在交集，则通过
    #         # allcheck = set(check).intersection(set(checks))
    #         # if allcheck:
    #         #     pass
    #         # else:
    #         #     return Message.json_mess(22, "无此权限", "")
    #         for i in check:
    #             for j in checks:
    #                 if str(i['power_url'])==str(j['power_url']):
    #                     pass
    #                 else:
    #                     return Message.json_mess(13, "无此权限", "")
        u = auth.TabUser.query.filter(auth.TabUser.id==id, auth.TabUser.status != 2).first()
        u.name = name
        u.real_name=real_name
        u.mobile = mobile
        u.role_id = role_id
        db.session.add(u)
        db.session.commit()
        res = {'user_id': u.id, 'role_id': u.role_id, 'status': u.status}
        key = "user_" + str(u.id)
        # 将基础的用户信息存入redis
        red_user_info.set(key, json.dumps(res))

        return Message.json_mess(0, '编辑成功', '')
    except Exception, e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')


def edit_password(id,password,token):
    try:
        cur.reconnect()
        # 获取token的body解析出的json
        body = get_token_body(token)
        add_role_id = body['role_id']
        u = auth.TabUser.query.filter(auth.TabUser.id == id, auth.TabUser.status != 2).first()
        # 检查调用接口的角色是否有权限
    #     if add_role_id > 0:
    #         sql = """SELECT * FROM tab_role_power a
    # LEFT JOIN tab_power b on a.power_id=b.id
    # where a.role_id=%s and b.type=3"""
    #         check = cur.query(sql, add_role_id)
    #         checks = cur.query(sql,u.role_id)
    #         # 被添加的角色不能拥有多个部门权限
    #         if len(checks) > 1:
    #             return Message.json_mess(13, "无此权限", "")
    #         # 查询两个权限数组的交集，如果存在交集，则通过
    #         # allcheck = set(check).intersection(set(checks))
    #         # if allcheck:
    #         #     pass
    #         # else:
    #         #     return Message.json_mess(22, "无此权限", "")
    #         for i in check:
    #             for j in checks:
    #                 if str(i['power_url'])==str(j['power_url']):
    #                     pass
    #                 else:
    #                     return Message.json_mess(13, "无此权限", "")

        word = str(password)
        # 生产盐，然后将密码和盐拼接一起MD5加密存入数据库
        u.salt = gen_salt(6)
        word = word + str(u.salt)
        password_md5 = hashlib.md5(word).hexdigest()
        u.password = password_md5
        db.session.add(u)
        db.session.commit()


        return Message.json_mess(0, '编辑成功', '')
    except Exception, e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')

def change_password(old_password,new_password,token):
    try:
        cur.reconnect()
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
    except Exception, e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '修改失败', '')


def delete_user(id,token):
    try:
        cur.reconnect()
        u = auth.TabUser.query.filter(auth.TabUser.id==id, auth.TabUser.status != 2).first()
        # 获取token的body解析出的json
        body = get_token_body(token)
        add_role_id = body['role_id']
        # 检查调用接口的角色是否有权限
    #     if add_role_id > 0:
    #         sql = """SELECT * FROM tab_role_power a
    # LEFT JOIN tab_power b on a.power_id=b.id
    # where a.role_id=%s and b.type=3"""
    #         check = cur.query(sql, add_role_id)
    #         checks = cur.query(sql, u.role_id)
    #         # 被删除的角色不能拥有多个部门权限
    #         if len(checks) > 1:
    #             return Message.json_mess(13, "无此权限", "")
    #         # 查询两个权限数组的交集，如果存在交集，则通过
    #         # allcheck = set(check).intersection(set(checks))
    #         # if allcheck:
    #         #     pass
    #         # else:
    #         #     return Message.json_mess(22, "无此权限", "")
    #         for i in check:
    #             for j in checks:
    #                 if str(i['power_url'])==str(j['power_url']):
    #                     pass
    #                 else:
    #                     return Message.json_mess(13, "无此权限", "")
        u.status = 2
        db.session.add(u)
        db.session.commit()
        key = "user_" + str(u.id)
        # 将基础的用户信息存入redis
        red_user_info.delete(key)
        return Message.json_mess(0, '删除成功', '')
    except Exception, e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')

def user_data(token,page_index,page_size):
    try:
        page_size=int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        body=get_token_body(token)
        role_id=body['role_id']
    #     if int(role_id)>0:
    #         sql="""SELECT power_id FROM tab_role_power a
    # LEFT JOIN tab_power b on a.power_id=b.id
    # WHERE b.type=3 and a.role_id=%s"""
    #         data=cur.query(sql,role_id)
    #         list=""
    #         for i in data:
    #             power_id=","+str(i['power_id'])
    #             list=list+power_id
    #         list=list[1:]
    #         print  list
    #         sql="SELECT DISTINCT(role_id) FROM tab_role_power WHERE power_id in ("+list+")"
    #         data=cur.query(sql)
    #         list = ""
    #         for i in data:
    #             role_id = "," + str(i['role_id'])
    #             list = list + role_id
    #         list = list[1:]
    #         print  list
    #         sql="SELECT a.id,a.`name`,a.real_name,mobile,role_id,b.role_name,a.create_time FROM tab_user a LEFT JOIN tab_role b on a.role_id=b.id WHERE a.`status`!=2 AND role_id in ("+list+") ORDER BY a.create_time DESC LIMIT %s,%s"
    #         data=cur.query(sql,page_index,page_size)
    #         return Message.json_mess(0,"查询成功",data)
        if int(role_id) >=0:
            sql = "SELECT a.id,a.`name`,a.real_name,mobile,role_id,case when a.role_id = 0 then '超级管理员' else b.role_name end as role_name,a.create_time FROM tab_user a LEFT JOIN tab_role b on a.role_id=b.id WHERE a.`status`!=2  ORDER BY a.create_time DESC LIMIT %s,%s"
            data = cur.query(sql, page_index, page_size)
            sql_count = "SELECT count(1) as count FROM tab_user a LEFT JOIN tab_role b on a.role_id=b.id WHERE a.`status`!=2 "
            count = cur.get(sql_count)
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}
            return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')

def user_data_single(user_id):
    try:
        sql = "select * from tab_user where id=%s"
        data = cur.query(sql, user_id)
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
        db.session.add(u)
        db.session.commit()
        return Message.json_mess(0,'添加成功','')
    except Exception,e:
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
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')

def delete_role(id):
    try:
        cur.reconnect()
        u=auth.TabRole.query.filter(auth.TabRole.id==id,auth.TabRole.status!=2).first()
        u.status=2
        db.session.add(u)
        db.session.commit()
        sql="delete from tab_role_power where role_id="+str(id)
        cur.execute(sql)
        key="role_"+str(id)
        red_user_info.delete(key)
        return Message.json_mess(0,'删除成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')
    finally:
        cur.close()

def role_data(page_index,page_size):
    try:
        cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        sql = "select * from tab_role where status!=2 limit %s,%s"
        data = cur.query(sql, page_index, int(page_size))
        sql_count = "select count(1) as count from tab_role where status!=2"
        count = cur.get(sql_count)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, "查询失败", "")
    finally:
        cur.close()


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
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')



def delete_power(id):
    try:
        u=auth.TabPower.query.filter(auth.TabPower.id==id).first()
        db.session.delete(u)
        db.session.commit()
        res = { 'power_url': u.power_url, 'power_name': u.power_name, 'power_type': u.type,'power_id': u.id}
        sql= "select role_id from tab_role_power where power_id=%s"
        data=cur.query(sql,id)
        if data:
            for role_id in data:
                key="role_"+str(role_id['role_id'])
                red_user_info.srem(key,json.dumps(res))
        sql = "delete from tab_role_power where power_id=%s"
        cur.execute(sql,id)
        sql = "delete from tab_menu_power where power_id=%s"
        cur.execute(sql, id)
        return Message.json_mess(0,'删除成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')


def power_data(type,page_index,page_size):
    try:
        cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        if int(type) >0:
            sql = """select * from tab_power where type=%s order by type asc,id desc limit %s,%s """
            data = cur.query(sql,int(type), page_index, page_size)
            sql_count = "select count(*) as count from tab_power where type=%s"
            count = cur.get(sql_count,int(type))
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}
        elif int(type)==0:
            sql = """select * from tab_power order by type asc,id desc limit %s,%s """
            data = cur.query(sql, page_index, page_size)
            sql_count = "select count(*) as count from tab_power "
            count = cur.get(sql_count)
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, "查询失败", "")
    finally:
        cur.close()

def add_role_power(role_id,power_ids):
    try:
        cur.reconnect()
        if role_id<0:
            return Message.json_mess(7,'添加失败','')
        sql="delete from tab_role_power where role_id=%s"
        cur.execute(sql,str(role_id))
        key = "role_" + str(role_id)
        red_user_info.delete(key)
        for i in power_ids:
            if i>0:
                u=auth.TabRolePower()
                u.role_id=role_id
                u.power_id=i
                db.session.add(u)
                db.session.commit()
                a=auth.TabPower.query.filter(auth.TabPower.id==u.power_id).first()
                url=a.power_url
                key="role_"+str(role_id)
                res={'power_id':u.power_id,'power_url':url,'power_name':a.power_name,'power_type':a.type}
                red_user_info.sadd(key,json.dumps(res))


        return Message.json_mess(0, '添加成功', '')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')
    finally:
        cur.close()

def add_role_powers(role_ids,power_id):
    try:
        cur.reconnect()
        if power_id<0:
            return Message.json_mess(7,'添加失败','')
        sql="delete from tab_role_power where power_id=%s"
        cur.execute(sql,str(power_id))

        for i in role_ids:
            if i>0:
                key = "role_" + str(i)
                # red_user_info.delete(key)
                u=auth.TabRolePower()
                u.role_id=i
                u.power_id=power_id
                db.session.add(u)
                db.session.commit()
                a=auth.TabPower.query.filter(auth.TabPower.id==u.power_id).first()
                url=a.power_url
                key="role_"+str(i)
                res={'power_id':u.power_id,'power_url':url,'power_name':a.power_name,'power_type':a.type}
                red_user_info.sadd(key,json.dumps(res))


        return Message.json_mess(0, '添加成功', '')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')
    finally:
        cur.close()

def add_role_power_single(role_id,power_id):
    try:
        if role_id<0:
            return Message.json_mess(7,'添加失败','')
        if int(role_id)>0 and int(power_id) >0:
            check=auth.TabRolePower.query.filter(auth.TabRolePower.role_id==role_id,auth.TabRolePower.power_id==power_id).first()
            if check:
                return Message.json_mess(11, '添加重复', '')
            else:
                u=auth.TabRolePower()
                u.role_id=role_id
                u.power_id=power_id
                db.session.add(u)
                db.session.commit()
                a=auth.TabPower.query.filter(auth.TabPower.id==u.power_id).first()
                url=a.power_url
                key="role_"+str(role_id)
                res={'power_id':u.power_id,'power_url':url,'power_name':a.power_name,'power_type':a.type}
                red_user_info.sadd(key,json.dumps(res))

        return Message.json_mess(0, '添加成功', '')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')


def delete_device(token,device_id):
    try:
        body = get_token_body(token)
        role_id = body['role_id']
        if int(role_id)==0:
            return Message.json_mess(0, '此为超管无法解绑', '')
        u = auth.TabPower.query.filter(auth.TabPower.power_url == str(device_id),auth.TabPower.type == 4).first()
        return delete_role_power(role_id,u.id)
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')


def delete_role_power(role_id,power_id):
    try:
        a=auth.TabRolePower.query.filter(auth.TabRolePower.role_id==role_id,auth.TabRolePower.power_id==power_id).first()
        db.session.delete(a)
        db.session.commit()
        u = auth.TabPower.query.filter(auth.TabPower.id == power_id).first()
        res = { 'power_url': u.power_url, 'power_name': u.power_name, 'power_type': u.type,'power_id': u.id}
        key="role_"+str(role_id)
        red_user_info.srem(key,json.dumps(res))
        return Message.json_mess(0,'删除成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')

def role_power_data(role_id,page_index,page_size):
    try:
        cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        if int(role_id) > 0:
            sql = """SELECT a.role_id,b.role_name,a.power_id,c.power_name,c.power_url,c.type FROM tab_role_power a
                LEFT JOIN tab_role b on a.role_id=b.id
                LEFT JOIN tab_power c on a.power_id=c.id
                where a.role_id=%s order by a.role_id desc,c.type asc limit %s,%s"""
            data = cur.query(sql, role_id, page_index, page_size)
            sql_count = """SELECT count(1) as count FROM tab_role_power a
                LEFT JOIN tab_role b on a.role_id=b.id
                LEFT JOIN tab_power c on a.power_id=c.id
                where a.role_id=%s """
            count = cur.get(sql_count, role_id)
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}
        if int(role_id) == 0:
            sql="""SELECT a.role_id,b.role_name,a.power_id,c.power_name,c.power_url,c.type FROM tab_role_power a
            LEFT JOIN tab_role b on a.role_id=b.id
            LEFT JOIN tab_power c on a.power_id=c.id
            order by a.role_id desc,c.type asc limit %s,%s"""
            data=cur.query(sql,page_index,page_size)
            sql_count = """SELECT count(1) as count FROM tab_role_power a
            LEFT JOIN tab_role b on a.role_id=b.id
            LEFT JOIN tab_power c on a.power_id=c.id"""
            count = cur.get(sql_count)
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}


        return Message.json_mess(0,"查询成功",data)

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')
    finally:
        cur.close()

def device_role_data(power_id,page_index,page_size):
    try:
        cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)

        sql = """SELECT a.role_id,b.role_name,a.power_id,c.power_name,c.power_url,c.type FROM tab_role_power a
            LEFT JOIN tab_role b on a.role_id=b.id
            LEFT JOIN tab_power c on a.power_id=c.id
            where c.power_url=%s and c.type=4 order by a.role_id desc,c.type asc limit %s,%s"""
        data = cur.query(sql, power_id, page_index, page_size)
        sql_count = """SELECT count(1) as count FROM tab_role_power a
            LEFT JOIN tab_role b on a.role_id=b.id
            LEFT JOIN tab_power c on a.power_id=c.id
            where c.power_url=%s and c.type=4 """
        count = cur.get(sql_count, power_id)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}


        return Message.json_mess(0,"查询成功",data)

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')
    finally:
        cur.close()


def add_menu(name):
    try:
        check_name=auth.TabMenu.query.filter(auth.TabMenu.name==name).first()
        if check_name:
            return Message.json_mess(11,"菜单名重复","")
        u=auth.TabMenu()
        u.name=name
        db.session.add(u)
        db.session.commit()
        return Message.json_mess(0,'添加成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')

def edit_menu(id,name):
    try:
        check_name=auth.TabMenu.query.filter(auth.TabMenu.name==name,auth.TabMenu.id!=id).first()
        if check_name:
            return Message.json_mess(11,"菜单名重复","")
        u=auth.TabMenu.query.filter(auth.TabMenu.id==id).first()
        u.name=name
        db.session.add(u)
        db.session.commit()
        return Message.json_mess(0,'编辑成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')

def delete_menu(id):
    try:
        cur.reconnect()
        u=auth.TabMenu.query.filter(auth.TabMenu.id==id).first()
        db.session.delete(u)
        db.session.commit()
        sql="delete from tab_menu_power where menu_id="+str(id)
        cur.execute(sql)

        return Message.json_mess(0,'删除成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')
    finally:
        cur.close()

def menu_data(page_index,page_size):
    try:
        cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        sql = "select * from tab_menu order by id desc limit %s,%s"
        data = cur.query(sql, page_index, page_size)
        sql_count = "select count(*) as count from tab_menu"
        count = cur.get(sql_count)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, "查询失败", "")
    finally:
        cur.close()

def add_menu_power(menu_id,power_id):
    try:
        if int(menu_id)<0:
            return Message.json_mess(7,'添加失败','')
        if int(menu_id)>0 and int(power_id) >0:
            check=auth.TabMenuPower.query.filter(auth.TabMenuPower.menu_id==menu_id,auth.TabMenuPower.power_id==power_id).first()
            if check:
                return Message.json_mess(11, '添加重复', '')
            else:
                u=auth.TabMenuPower()
                u.menu_id=menu_id
                u.power_id=power_id
                db.session.add(u)
                db.session.commit()


        return Message.json_mess(0, '添加成功', '')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')


def delete_menu_power(menu_id,power_id):
    try:
        a=auth.TabMenuPower.query.filter(auth.TabMenuPower.menu_id==menu_id,auth.TabMenuPower.power_id==power_id).first()
        db.session.delete(a)
        db.session.commit()

        return Message.json_mess(0,'删除成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')

def menu_power_data(menu_id,page_index,page_size):
    try:
        cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        if int(menu_id) > 0:
            sql = """SELECT a.menu_id,b.`name` as menu_name,a.power_id,c.power_name,c.power_url,c.type FROM tab_menu_power a
            LEFT JOIN tab_menu b on a.menu_id=b.id
            LEFT JOIN tab_power c on a.power_id=c.id
            where a.menu_id=%s order by a.menu_id desc limit %s,%s"""
            data = cur.query(sql, int(menu_id), page_index, page_size)
            sql_count = """SELECT count(1) as count FROM tab_menu_power a
            LEFT JOIN tab_menu b on a.menu_id=b.id
            LEFT JOIN tab_power c on a.power_id=c.id where a.menu_id=%s"""
            count = cur.get(sql_count,int(menu_id))
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}
        if int(menu_id) == 0:
            sql="""SELECT a.menu_id,b.`name` as menu_name,a.power_id,c.power_name,c.power_url,c.type FROM tab_menu_power a
            LEFT JOIN tab_menu b on a.menu_id=b.id
            LEFT JOIN tab_power c on a.power_id=c.id
            order by a.menu_id desc limit %s,%s"""
            data=cur.query(sql,page_index,page_size)
            sql_count ="""SELECT count(1) as count FROM tab_menu_power a
            LEFT JOIN tab_menu b on a.menu_id=b.id
            LEFT JOIN tab_power c on a.power_id=c.id"""
            count = cur.get(sql_count)
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}


        return Message.json_mess(0,"查询成功",data)

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')
    finally:
        cur.close()


def log_data(user_id,role_id,start_time,end_time,type,page_index,page_size,power_id):
    try:
        cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        user_sql=""
        role_sql=""
        power_sql=""
        if int(type)>0 and int(power_id)>0:
            return Message.json_mess(10, '查询类型不匹配', '')

        if int(user_id)>0:
            user_sql=" and b.id="+str(user_id)

        if int(role_id) >= 0:
            role_sql=" and b.role_id="+str(role_id)
        if int(power_id)>0:
            power_sql=" and d.id="+str(power_id)

        if int(type) == 0:
            sql = """SELECT a.user_id,b.`name` as username,b.role_id,case when b.role_id = 0 then '超级管理员' else c.role_name end as role_name,a.url,d.power_name,date_format(a.create_time,'%%Y-%%m-%%d %%H:%%i:%%S') as create_time,a.type from tab_log a
LEFT JOIN tab_user b on a.user_id=b.id
LEFT JOIN tab_role c on b.role_id=c.id
LEFT JOIN tab_power d on a.url=d.power_url
where a.type=0 and d.type=1 and a.create_time>= %s and a.create_time <=%s """+user_sql+role_sql+power_sql+""" ORDER BY a.create_time DESC LIMIT %s,%s"""
            sql_count = """SELECT count(1) as count from tab_log a
LEFT JOIN tab_user b on a.user_id=b.id
LEFT JOIN tab_role c on b.role_id=c.id
LEFT JOIN tab_power d on a.url=d.power_url
where a.type=0 and d.type=1 and a.create_time>= %s and a.create_time <=%s """+user_sql+role_sql+power_sql
        if int(type) == 1:
            sql="""SELECT a.user_id,b.`name` as username,b.role_id,case when b.role_id = 0 then '超级管理员' else c.role_name end as role_name,a.url,date_format(a.create_time,'%%Y-%%m-%%d %%H:%%i:%%S') as create_time,a.type from tab_log a
LEFT JOIN tab_user b on a.user_id=b.id
LEFT JOIN tab_role c on b.role_id=c.id
where a.type=1 and a.create_time>= %s and a.create_time <=%s """+user_sql+role_sql+"""  ORDER BY a.create_time DESC LIMIT %s,%s"""
            sql_count = """SELECT count(1) as count from tab_log a
LEFT JOIN tab_user b on a.user_id=b.id
LEFT JOIN tab_role c on b.role_id=c.id
where a.type=1 and a.create_time>= %s and a.create_time <=%s """+user_sql+role_sql

        data = cur.query(sql, start_time, end_time, page_index, page_size)

        count = cur.get(sql_count, start_time, end_time)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0,"查询成功",data)

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')
    finally:
        cur.close()




def add_interface_category(name):
    try:
        check_name=auth.TabInterfaceCategory.query.filter(auth.TabInterfaceCategory.name==name).first()
        if check_name:
            return Message.json_mess(11,"接口分类名重复","")
        u=auth.TabInterfaceCategory()
        u.name=name
        db.session.add(u)
        db.session.commit()
        return Message.json_mess(0,'添加成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')

def edit_interface_category(id,name):
    try:
        check_name=auth.TabInterfaceCategory.query.filter(auth.TabInterfaceCategory.name==name,auth.TabInterfaceCategory.id!=id).first()
        if check_name:
            return Message.json_mess(11,"接口分类名重复","")
        u=auth.TabInterfaceCategory.query.filter(auth.TabInterfaceCategory.id==id).first()
        u.name=name
        db.session.add(u)
        db.session.commit()
        return Message.json_mess(0,'编辑成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')

def delete_interface_category(id):
    try:
        cur.reconnect()
        sql="delete from tab_interface_category where id="+str(id)
        cur.execute(sql)
        sql = "delete from tab_interface_category_power where interface_category_id=" + str(id)
        cur.execute(sql)

        return Message.json_mess(0,'删除成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')
    finally:
        cur.close()

def interface_category_data(page_index,page_size):
    try:
        cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        sql = "select * from tab_interface_category order by id desc limit %s,%s"
        data = cur.query(sql, page_index, page_size)
        sql_count = "select count(*) as count from tab_interface_category"
        count = cur.get(sql_count)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, "查询失败", "")
    finally:
        cur.close()

def add_interface_category_power(interface_category_id,power_id):
    try:
        if int(interface_category_id)<0:
            return Message.json_mess(7,'添加失败','')
        if int(interface_category_id)>0 and int(power_id) >0:
            check=auth.TabInterfaceCategoryPower.query.filter(auth.TabInterfaceCategoryPower.interface_category_id==interface_category_id,auth.TabInterfaceCategoryPower.power_id==power_id).first()
            if check:
                return Message.json_mess(11, '添加重复', '')
            else:
                u=auth.TabInterfaceCategoryPower()
                u.interface_category_id=interface_category_id
                u.power_id=power_id
                db.session.add(u)
                db.session.commit()


        return Message.json_mess(0, '添加成功', '')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')

def add_interface_category_powers(req):
    try:
        cur.reconnect()
        com_sql = ""
        for i in req:
            interface_category_id = i['interface_category_id']
            power_id = i['power_id']
            check = "select * from tab_interface_category_power where interface_category_id=%s and power_id=%s"
            c = cur.get(check, interface_category_id, power_id)
            if c:
                pass
            else:
                com_sql = com_sql + ",(" + str(interface_category_id) + "," + str(power_id)+ ")"

        com_sql = com_sql[1:]
        if com_sql != "":
            sql = "insert into tab_interface_category_power(interface_category_id,power_id) values " + com_sql
            cur.execute(sql)


        return Message.json_mess(0, '添加成功', '')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')





def delete_interface_category_power(interface_category_id,power_id):
    try:
        a=auth.TabInterfaceCategoryPower.query.filter(auth.TabInterfaceCategoryPower.interface_category_id==interface_category_id,auth.TabInterfaceCategoryPower.power_id==power_id).first()
        db.session.delete(a)
        db.session.commit()

        return Message.json_mess(0,'删除成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')

def interface_category_power_data(interface_category_id,page_index,page_size):
    try:
        cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)

        sql = """SELECT a.interface_category_id,b.name as interface_category_name,a.power_id,c.power_name,c.power_url,c.type FROM tab_interface_category_power a
            LEFT JOIN tab_interface_category b on a.interface_category_id=b.id
            LEFT JOIN tab_power c on a.power_id=c.id
            where a.interface_category_id=%s order by a.id desc  limit %s,%s"""
        data = cur.query(sql, interface_category_id, page_index, page_size)
        sql_count = """SELECT count(1) as count FROM tab_interface_category_power a
            LEFT JOIN tab_interface_category b on a.interface_category_id=b.id
            LEFT JOIN tab_power c on a.power_id=c.id
            where a.interface_category_id=%s"""
        count = cur.get(sql_count, interface_category_id)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}


        return Message.json_mess(0,"查询成功",data)

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')
    finally:
        cur.close()
















def get_token_body(token):
    token = str(token)
    token = token.split('.')
    payload = token[1]
    payload_d = decode_token_bytes(payload)
    data = json.loads(payload_d.decode("utf8"))
    return data



def token_login(data):
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
            red.set(user_id,info)
            red_access_token.set(user_id,access_token)
            red_access_token.expire(user_id,config.access_token_expire)
            red_refresh_token.set(user_id,refresh_token)
            red_refresh_token.expire(user_id,config.refresh_token_expire)


        res={"access_token":access_token,"refresh_token":refresh_token,"expires":expires}
        return res
    except Exception,e:
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
        print "header:"+header
        data = data.copy()
        user_id=data["user_id"]
        if "expires" not in data:
            expires= time.time() + TIMEOUT
            data["expires"] = expires
            print "expires:"+str(expires)
        payload = json.dumps(data).encode("utf8")
        # 生成签名
        payload=encode_token_bytes(payload)
        print "payload:"+payload

        s_key=gen_salt(6)
        s_salt=gen_salt(6)
        print "key:"+s_key
        print "salt:"+s_salt
        signer=_get_signature(header+payload+s_salt+s_key)

        print "sign:"+signer
        token=header+"."+payload+"."+signer
        print "token:"+token
        info={"user_id":user_id,"token":token,"key":s_key,"salt":s_salt,"expires":expires}
        # info=str(info)
        return info
    except Exception,e:
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




