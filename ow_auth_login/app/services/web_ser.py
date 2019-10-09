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


def test():
    return 1


def login(platform,mobile,password):
    try:
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
            manage.red.set(user_id,info)


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




