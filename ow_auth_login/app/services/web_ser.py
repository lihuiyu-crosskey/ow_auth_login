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
import manage
import urllib
import re




def login(platform,mobile,password):
    try:
        check=check_mobile(mobile)
        if check!=0:
            return Message.json_mess(21,'手机格式不正确','')
        manage.cur.reconnect()
        sql="select * from tab_user where mobile=%s and status!=2 limit 1"
        data=manage.cur.get(sql,str(mobile))
        if data:
            if int(data['status'])==1:
                return Message.json_mess(14, "账户已经被封", "")
            # 密码加盐加密
            word = str(password) + str(data['salt'])
            word = hashlib.md5(word).hexdigest()
            # 密码验证
            if word == str(data['password']):
                role_type = 0
                if int(data['role_id']) > 0:
                    sql="select * from tab_role where id=%s and status!=2 limit 1"
                    role=manage.cur.get(sql,data['role_id'])
                    role_type =role['type']

                platform_type=''
                if platform=='iOS' or platform=='Android':
                    platform_type='mobile'
                else:
                    platform_type='web'
                # 组合token的body
                self = {"user_id": data['id'], 'role_id': data['role_id'], 'mobile': data['mobile'],
                        'status': data['status'], 'role_type': role_type,'platform_type':platform_type}
                # 生产token
                res = token_login(dict(self))
                res = res.copy()
                access_token = res["access_token"]
                refresh_token = res["refresh_token"]
                expires = res["expires"]
                token = {'access_token': access_token, 'refresh_token': refresh_token, 'expires': expires}
                return Message.json_mess(0, '登陆成功', token)
            else:
                return Message.json_mess(18, '密码错误', '')
        else:
            return Message.json_mess(15, '账户不存在', '')

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(12, '登录失败', '')
    finally:
        manage.cur.close()


def find_password(mobile,password,code):
    try:
        manage.cur.reconnect()
        manage.cur.reconnect()
        check=check_mobile(mobile)
        if check==0:
            real_code=manage.red.get("mobile_"+str(mobile))
            if str(real_code)==str(code):
                sql='select * from tab_user where status!=2 and mobile=%s limit 1'
                data=manage.cur.get(sql,mobile)
                if data:
                    word = str(password)
                    salt = gen_salt(6)
                    word = word + str(salt)
                    password_md5 = hashlib.md5(word).hexdigest()
                    sql='update tab_user set password=%s,salt=%s where id=%s'
                    manage.cur.execute(sql,password_md5,salt,data['id'])
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
    finally:
        manage.cur.close()



def mobile_get_code(mobile):
    try:
        check=check_mobile(mobile)
        if check==0:
            mobile=str(mobile)
            code=get_random_num(6)
            red_key="mobile_"+mobile
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

        mess64= base64.b64encode(message.encode(encoding="utf-8"))
        messcode=urllib.parse.quote(mess64)
        res={'sid':'710446','mobi':nums,'sign':'fc08d39e714e4355881baf769ec8b940','msg':messcode}
        rs=Message.post_json_request(config.sms_url,res,1)
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
            check_code = manage.red.get('mobile_' + str(mobile))
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
def mobile_reg(password,mobile,nick_name,user_img,code):
    try:
        manage.cur.reconnect()
        #手机号查重
        sql='select * from tab_user where mobile=%s and status!=2 limit 1'
        check_name=manage.cur.get(sql,str(mobile))
        if check_name:
            return Message.json_mess(11,"手机号重复","")
        check_code=manage.red.get('mobile_'+str(mobile))
        if check_code is None:
            return Message.json_mess(22, "验证码不存在", "")
        if check_code!=code:
            return Message.json_mess(23, "验证码校验失败", "")
        sql='select id from tab_role where type=1 and status!=2 limit 1'
        role=manage.cur.get(sql)
        role_id=role['id']
        new_pass=give_password(password)
        sql='INSERT into tab_user(nick_name,mobile,`password`,role_id,`status`,create_time,salt,user_img,is_real) VALUES (%s,%s,%s,%s,0,now(),%s,%s,0)'
        user_id=manage.cur.execute_lastrowid(sql,nick_name,mobile,new_pass['password'],role_id,new_pass['salt'],user_img)
        # res={'user_id':user_id,'role_id':role_id,'status':0,'role_type':1}
        # key="user_info_"+str(user_id)
        # #将基础的用户信息存入redis
        # manage.red.set(key,json.dumps(res))
        return Message.json_mess(0,'注册成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        #添加时一旦发生错误，回滚
        sql='update tab_user set status=2 where mobile=%s'
        manage.cur.execute(sql,mobile)
        return Message.json_mess(7, '注册失败', '')
    finally:
        manage.cur.close()

#用refresh_token换取access_token
def refresh_token(token):
    try:
        tokens=str(token)
        token = str(token)
        token = token.split('.')
        header = token[0]
        payload = token[1]
        header_c=decode_token_bytes(header)
        header_c=ast.literal_eval(header_c)
        header_c=json.dumps(header_c)
        data = json.loads(header_c.decode("utf8"))
        type = data['token_type']
        if str(type) != "refresh":
            return Message.json_mess(4,'token类型错误','')
        payload_d = decode_token_bytes(payload)
        data = json.loads(payload_d.decode("utf8"))
        user_id = data.get('user_id')
        platform_type=data['platform_type']
        refresh_token=tokens
        if platform_type=='mobile':
            orgin_refresh_token=manage.red.get('mobile_refresh_token_' + str(user_id))
            if int(user_id) > 0:
                info = manage.red.get('mobile_token_info_' + str(user_id))
            else:
                return Message.json_mess(20, '用户id不合法', '')
        else:
            orgin_refresh_token = manage.red.get('web_refresh_token_' + str(user_id))
            if int(user_id) > 0:
                info = manage.red.get('web_token_info_' + str(user_id))
            else:
                return Message.json_mess(20, '用户id不合法', '')
        if orgin_refresh_token:
            if orgin_refresh_token==refresh_token:
                pass
            else:
                return Message.json_mess(20, 'refresh_token签名验证错误', '')
        else:
            return Message.json_mess(1, 'token过期', '')


        info = ast.literal_eval(info)
        info = json.dumps(info)
        info = json.loads(info)
        refresh_key=info["refresh_key"]
        refresh_salt=info["refresh_salt"]

        sql = "select * from tab_user where id=%s and status!=2 limit 1"
        data = manage.cur.get(sql, str(user_id))
        if data:
            if int(data['status']) == 1:
                return Message.json_mess(14, "账户已经被封", "")

        self = {"user_id": user_id, 'role_id': data['role_id'], 'nick_name': data['nick_name'], 'mobile': data['mobile'],
                'status': data['status']}

        a = gen_token(0, dict(self), config.access_token_expire)
        a = a.copy()
        user_id = a["user_id"]
        access_token = a["token"]
        expires = a["expires"]
        access_key = a["key"]
        access_salt = a["salt"]
        info = {"user_id": user_id, "access_token": access_token, "access_key": access_key,
                "access_salt": access_salt, "expires": expires, "refresh_token": refresh_token,
                "refresh_key": refresh_key, "refresh_salt": refresh_salt}
        info = str(info)

        if int(user_id) > 0:

            if platform_type == 'mobile':
                manage.red.set('mobile_token_info_' + str(user_id), info)
                manage.red.set('mobile_access_token_' + str(user_id), access_token)
                manage.red.expire('mobile_access_token_' + str(user_id), config.access_token_expire)

            elif platform_type == 'web':
                manage.red.set('web_token_info_' + str(user_id), info)
                manage.red.set('web_access_token_' + str(user_id), access_token)
                manage.red.expire('web_access_token_' + str(user_id), config.access_token_expire)


        token={'access_token':access_token,'refresh_token':refresh_token,'expires':expires}
        return Message.json_mess(0, 'token刷新成功', token)

    except Exception as e:
        print (e)
        current_app.logger.error(str(e))
        return Message.json_mess(17, "刷新token失败", "")


def add_user(password,mobile,nick_name,user_img,role_id):
    try:
        manage.cur.reconnect()
        if int(role_id)<=0:
            return Message.json_mess(13,"无此权限","")
        #手机号查重
        sql='select * from tab_user where mobile=%s and status!=2 limit 1'
        check_name=manage.cur.get(sql,str(mobile))
        if check_name:
            return Message.json_mess(11,"手机号重复","")
        new_pass=give_password(password)
        sql='INSERT into tab_user(nick_name,mobile,`password`,role_id,`status`,create_time,salt,user_img,is_real) VALUES (%s,%s,%s,%s,0,now(),%s,%s,0)'
        user_id=manage.cur.execute_lastrowid(sql,nick_name,mobile,new_pass['password'],role_id,new_pass['salt'],user_img)
        # res={'user_id':user_id,'role_id':role_id,'status':0,'role_type':1}
        # key="user_info_"+str(user_id)
        # #将基础的用户信息存入redis
        # manage.red.set(key,json.dumps(res))
        return Message.json_mess(0,'添加成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        #添加时一旦发生错误，回滚
        sql='update tab_user set status=2 where mobile=%s'
        manage.cur.execute(sql,mobile)
        return Message.json_mess(7, '添加失败', '')
    finally:
        manage.cur.close()

def edit_user(user_id,mobile,nick_name,user_img,role_id):
    try:
        manage.cur.reconnect()
        if int(role_id)<=0:
            return Message.json_mess(13,"无此权限","")
        #手机号查重
        sql='select * from tab_user where mobile=%s and id!=%s and status!=2 limit 1'
        check_name=manage.cur.get(sql,str(mobile),user_id)
        if check_name:
            return Message.json_mess(11,"手机号重复","")
        sql='update tab_user set nick_name=%s,mobile=%s,role_id=%s,user_img=%s where id=%s'
        user_id=manage.cur.execute_lastrowid(sql,nick_name,mobile,role_id,user_img,user_id)
        return Message.json_mess(0,'编辑成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        #添加时一旦发生错误，回滚
        sql='update tab_user set status=2 where mobile=%s'
        manage.cur.execute(sql,mobile)
        return Message.json_mess(8, '编辑失败', '')
    finally:
        manage.cur.close()

def delete_user(user_id):
    try:
        manage.cur.reconnect()
        sql='select * from tab_user where id=%s limit 1'
        check=manage.cur.get(sql,user_id)
        if int(check['role_id'])==0:
            return Message.json_mess(13, '无法删除超级管理员', '')
        sql='update tab_user set status=2 where id=%s'
        manage.cur.execute(sql,user_id)
        return Message.json_mess(0,'删除成功','')

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')
    finally:
        manage.cur.close()

def force_change_password(user_id,password):
    try:
        manage.cur.reconnect()
        new_pass=give_password(password)
        sql='update tab_user set password=%s,salt=%s where id=%s'
        manage.cur.execute(sql,new_pass['password'],new_pass['salt'],user_id)
        return Message.json_mess(0, '修改成功', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '编辑失败', '')
    finally:
        manage.cur.close()

def change_password(old_password,new_password,token):
    try:
        manage.cur.reconnect()
        # 获取token的body解析出的json
        body = get_token_body(token)
        id = body['user_id']
        sql='select * from tab_user where id=%s and status!=2 limit 1'
        u=manage.cur.get(sql,id)
        checkpass=str(old_password)+str(u['salt'])
        checkpass=hashlib.md5(checkpass).hexdigest()
        if str(checkpass) == str(u['password']):
            the_pass=give_password(new_password)
            sql='update tab_user set password=%s,salt=%s where id=%s'
            manage.cur.execute(sql,the_pass['password'],the_pass['salt'],id)
            return Message.json_mess(0, '修改成功', '')
        else:
            return Message.json_mess(18, '原始密码不正确', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '修改失败', '')
    finally:
        manage.cur.close()

def user_data(nick_name,mobile,role_id, page_index, page_size):
    try:
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        real_name_sql = ''
        if nick_name != '':
            real_name_sql = " and a.nick_name like '%%" + str(nick_name) + "%%' "
        mobile_sql = ''
        if mobile != '':
            mobile_sql = " and a.mobile like '%%" + str(mobile) + "%%' "
        role_id_sql = ''
        if int(role_id) >=0:
            role_id_sql = ' and a.role_id=' + str(role_id)


        sql = "SELECT a.id,a.nick_name,mobile,role_id,case when a.role_id = 0 then '超级管理员' else b.role_name end as role_name,a.create_time FROM tab_user a LEFT JOIN tab_role b on a.role_id=b.id WHERE a.`status`!=2 "+real_name_sql+mobile_sql+role_id_sql+" ORDER BY a.create_time DESC LIMIT %s,%s"
        data = manage.cur.query(sql, page_index, page_size)
        sql_count = "SELECT count(1) as count FROM tab_user a LEFT JOIN tab_role b on a.role_id=b.id WHERE a.`status`!=2 "+real_name_sql+mobile_sql+role_id_sql
        count = manage.cur.get(sql_count)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')




def add_role(role_name):
    try:
        manage.cur.reconnect()
        sql='insert into tab_role(role_name,status,type) values (%s,0,0)'
        manage.cur.execute(sql,role_name)
        return Message.json_mess(0, '添加成功', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')
    finally:
        manage.cur.close()

def edit_role(role_id,role_name):
    try:
        manage.cur.reconnect()
        sql='select * from tab_role where role_name=%s and id!=%s and status!=2 limit 1'
        check=manage.cur.get(sql,role_name,role_id)
        if check:
            return Message.json_mess(11,"角色名称重复","")
        sql='update tab_role set role_name=%s where id=%s'
        manage.cur.execute(sql,role_name,role_id)
        return Message.json_mess(0,'修改成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '修改失败', '')
    finally:
        manage.cur.close()

def delete_role(role_id):
    try:
        manage.cur.reconnect()
        sql='update tab_role set status=2 where id=%s'
        manage.cur.execute(sql,role_id)
        return Message.json_mess(0,'删除成功','')

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')
    finally:
        manage.cur.close()

def role_data(role_name,page_index,page_size):
    try:
        manage.cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        name_sql = ''
        if role_name != '':
            name_sql = " and role_name like '%%" + str(role_name) + "%%' "
        sql = "select * from tab_role where status!=2 "+name_sql+" order by id desc limit %s,%s"
        data = manage.cur.query(sql, page_index, int(page_size))
        sql_count = "select count(1) as count from tab_role where status!=2"+name_sql
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
        manage.cur.reconnect()
        sql='insert into tab_power_group(name) values (%s)'
        manage.cur.execute(sql,name)
        return Message.json_mess(0, '添加成功', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')
    finally:
        manage.cur.close()

def edit_power_group(id,name):
    try:
        manage.cur.reconnect()
        sql='select * from tab_power_group where name=%s and id!=%s  limit 1'
        check=manage.cur.get(sql,name,id)
        if check:
            return Message.json_mess(11,"权限组名称重复","")
        sql='update tab_power_group set name=%s where id=%s'
        manage.cur.execute(sql,name,id)
        return Message.json_mess(0,'修改成功','')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(8, '修改失败', '')
    finally:
        manage.cur.close()

def delete_power_group(id):
    try:
        manage.cur.reconnect()
        sql='delete from tab_power_group where id=%s'
        manage.cur.execute(sql,id)
        return Message.json_mess(0,'删除成功','')

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')
    finally:
        manage.cur.close()

def power_group_data(name,page_index,page_size):
    try:
        manage.cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        name_sql = ''
        if name != '':
            name_sql = " where name like '%%" + str(name) + "%%' "
        sql = "select * from tab_power_group "+name_sql+"  order by id desc  limit %s,%s"
        data = manage.cur.query(sql, page_index, int(page_size))
        sql_count = "select count(1) as count from tab_power_group "+name_sql
        count = manage.cur.get(sql_count)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, "查询失败", "")
    finally:
        manage.cur.close()


def delete_power(id):
    try:
        manage.cur.reconnect()
        sql='delete from tab_power where id=%s'
        manage.cur.execute(sql,id)
        return Message.json_mess(0,'删除成功','')

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(9, '删除失败', '')
    finally:
        manage.cur.close()

def power_data(power_name,power_code,power_mark,type,page_index,page_size):
    try:
        manage.cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        name_sql = ''
        if power_name != '':
            name_sql = " and power_name like '%%" + str(power_name) + "%%' "
        code_sql=''
        if power_code!='':
            code_sql=" and power_code like '%%"+str(power_code)+"%%'"
        mark_sql=''
        if power_mark!='':
            mark_sql=" and power_mark ='"+power_mark+"'"
        type_sql=''
        if int(type)>0:
            type_sql=" and type="+type
        sql = "select * from tab_power_group where 0=0  "+name_sql+code_sql+mark_sql+type_sql+"  order by id desc  limit %s,%s"
        data = manage.cur.query(sql, page_index, int(page_size))
        sql_count = "select count(1) as count from tab_power_group "+name_sql+code_sql+mark_sql+type_sql
        count = manage.cur.get(sql_count)
        page_count = count['count']
        data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, "查询失败", "")
    finally:
        manage.cur.close()


def add_role_power_group(role_id,power_group_ids):
    try:
        manage.cur.reconnect()
        sql='delete from tab_role_power_group where role_id=%s'
        manage.cur.execute(sql,role_id)
        insert_sql = ""
        if power_group_ids:
            for power_group_id in power_group_ids:
                if power_group_id>0:
                    insert_sql=insert_sql+" ("+str(role_id)+","+str(power_group_id)+"),"

            insert_sql = insert_sql[0:len(insert_sql) - 1]
            other_sql = "insert into tab_role_power_group(role_id,power_group_id) values " + insert_sql
            manage.cur.execute(other_sql)


        return Message.json_mess(0, '添加成功', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')
    finally:
        manage.cur.close()

def role_power_group_data(role_id,page_index,page_size):
    try:
        manage.cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        data=''
        if int(role_id) > 0:
            sql = 'select role_id,power_group_id from tab_role_power_group where role_id=%s limit %s,%s'
            data = manage.cur.query(sql, role_id, page_index, page_size)
            sql_count = """SELECT count(1) as count FROM tab_role_power_group where role_id=%s """
            count = manage.cur.get(sql_count, role_id)
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0,"查询成功",data)

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')
    finally:
        manage.cur.close()


def add_power_group_power(power_group_id, power_ids):
    try:
        manage.cur.reconnect()
        sql = 'delete from tab_power_group_power where power_group_id=%s'
        manage.cur.execute(sql, power_group_id)
        insert_sql = ""
        if power_ids:
            for power_id in power_ids:
                if power_id > 0:
                    insert_sql = insert_sql + " (" + str(power_group_id) + "," + str(power_id) + "),"

            insert_sql = insert_sql[0:len(insert_sql) - 1]
            other_sql = "insert into tab_power_group_power(power_group_id,power_id) values " + insert_sql
            manage.cur.execute(other_sql)

        return Message.json_mess(0, '添加成功', '')
    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')
    finally:
        manage.cur.close()


def power_group_power_data(power_group_id, page_index, page_size):
    try:
        manage.cur.reconnect()
        page_size = int(page_size)
        page_index = (int(page_index) - 1) * int(page_size)
        data = ''
        if int(power_group_id) > 0:
            sql = 'select power_group_id,power_id from tab_power_group_power where power_group_id=%s limit %s,%s'
            data = manage.cur.query(sql, power_group_id, page_index, page_size)
            sql_count = """SELECT count(1) as count FROM tab_power_group_power where power_group_id=%s """
            count = manage.cur.get(sql_count, power_group_id)
            page_count = count['count']
            data = {'data_info': data, 'page_count': page_count}
        return Message.json_mess(0, "查询成功", data)

    except Exception as e:
        current_app.logger.error(str(e))
        return Message.json_mess(10, '查询失败', '')
    finally:
        manage.cur.close()




def give_password(password):
    word = str(password)
    # 生产盐，然后将密码和盐拼接一起MD5加密存入数据库
    salt = gen_salt(6)
    word = word + str(salt)
    password_md5 = hashlib.md5(word).hexdigest()
    password = password_md5
    res={'password':password,'salt':salt}
    return res



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

            if data['platform_type']=='mobile':
                manage.red.set('mobile_token_info_' + str(user_id), info)
                manage.red.set('mobile_access_token_'+str(user_id),access_token)
                manage.red.expire('mobile_access_token_'+str(user_id),config.access_token_expire)
                manage.red.set('mobile_refresh_token_'+str(user_id),refresh_token)
                manage.red.expire('mobile_refresh_token_' + str(user_id), config.refresh_token_expire)
            elif data['platform_type'] == 'web':
                manage.red.set('web_token_info_' + str(user_id), info)
                manage.red.set('web_access_token_' + str(user_id), access_token)
                manage.red.expire('web_access_token_' + str(user_id), config.access_token_expire)
                manage.red.set('web_refresh_token_' + str(user_id), refresh_token)
                manage.red.expire('web_refresh_token_' + str(user_id), config.refresh_token_expire)


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




