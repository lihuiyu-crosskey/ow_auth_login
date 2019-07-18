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
from urllib import quote,unquote
import manage






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
            manage.red_access_token.set(user_id,access_token)
            manage.red_access_token.expire(user_id,config.access_token_expire)
            manage.red_refresh_token.set(user_id,refresh_token)
            manage.red_refresh_token.expire(user_id,config.refresh_token_expire)


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




