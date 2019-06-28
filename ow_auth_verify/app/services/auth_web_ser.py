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






def get_token_body(token):
    token = str(token)
    token = token.split('.')
    payload = token[1]
    payload_d = decode_token_bytes(payload)
    data = json.loads(payload_d.decode("utf8"))
    return data


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
        res=verify_token(1,tokens)
        if int(res)==1:
            return Message.json_mess(20, 'refresh_token签名验证错误', '')
        elif int(res)==3:
            return Message.json_mess(17, '刷新token失败', '')
        elif int(res)==0 or int(res)==2:
            payload_d = decode_token_bytes(payload)
            data = json.loads(payload_d.decode("utf8"))
            user_id = data.get('user_id')
            # imei=data.get('imei')
            if int(user_id)!=0:
                info = red.get(user_id)
            # else:
            #     info=red.get(imei)
            info = ast.literal_eval(info)
            info = json.dumps(info)
            info = json.loads(info)
            refresh_key=info["refresh_key"]
            refresh_salt=info["refresh_salt"]
            refresh_token=tokens
            if int(user_id)!=0:
                a = auth.TabUser.query.filter(auth.TabUser.id == user_id, auth.TabUser.status != 2).first()
                if int(a.status) == 1:
                    return Message.json_mess(14, "账户已经被封", "")
                b = auth.TabRole.query.filter(auth.TabRole.id == a.role_id, auth.TabRole.status != 2).first()
                if b:
                    self = {"user_id": a.id, 'role_id': a.role_id, 'username': a.name, 'mobile': a.mobile,
                            'status': a.status}
                else:
                    self = {"user_id": a.id, 'role_id': a.role_id, 'userName': a.name, 'mobile': a.mobile,
                            'status': a.status}
                other = {}
                self = dict(self, **other)
            else:
                self = {"user_id": user_id,}
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
            if int(user_id)!=0:
                red.delete(user_id)
                red.set(user_id, info)
                red_access_token.delete(user_id)
                red_access_token.set(user_id,access_token)
                red_access_token.expire(user_id,config.access_token_expire)
            # else:
            #     red.delete(imei)
            #     red.set(imei,info)
            #     red_access_token.delete(imei)
            #     red_access_token.set(imei, access_token)
            #     red_access_token.expire(imei, config.access_token_expire)
            token = {'access_token': access_token, 'refresh_token': refresh_token,
                     'expires': expires}
            return Message.json_mess(0, 'token刷新成功', token)

    except Exception,e:
        print e
        current_app.logger.error(str(e))
        return Message.json_mess(17, "刷新token失败", "")






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



# token验证
def verify_token(type,token):
    '''
    :param token: base64 str
    :return: 0正常1签名验证错误2token过期3未知错误
    '''
    try:
        res=0
        token=str(token)
        token=token.split('.')
        header=token[0]
        payload = token[1]
        sig = token[2]

        payload_d=decode_token_bytes(payload)
        data = json.loads(payload_d.decode("utf8"))
        user_id=data.get('user_id')
        # imei=data.get('imei')
        if int(user_id) !=0:
            info=red.get(user_id)
        # else:
        #     info=red.get(imei)
        info=ast.literal_eval(info)
        info=json.dumps(info)
        info=json.loads(info)
        if int(type)==0:
            salt=info['access_salt']
            key=info['access_key']
        elif int(type)==1:
            salt = info['refresh_salt']
            key = info['refresh_key']
        check_sig=_get_signature(header+payload+salt+key)
        # print time.asctime(time.localtime(time.time()))
        # print time.asctime(time.localtime(data.get('expires')))
        if sig!=check_sig:
            res=1
            return res

        if int(data.get('expires')) < int(time.time()):
            res=2
            return  res

        return res
    except Exception,e:
        print e
        current_app.logger.error(str(e))
        res=3
        return res


#权限验证
def verify_power(token, url, uid):
    try:
        #token解析
        tokens = str(token)
        token = str(token)
        token = token.split('.')
        header = token[0]
        payload = token[1]
        header_c = decode_token_bytes(header)
        header_c = ast.literal_eval(header_c)
        header_c = json.dumps(header_c)
        data = json.loads(header_c.decode("utf8"))
        type = data['token_type']
        if str(type) != "access":
            return Message.json_mess(4, 'token类型错误', '')
        res = verify_token(0, tokens)
        if int(res) == 1:
            return Message.json_mess(3, 'access_token签名验证错误', '')
        elif int(res) == 3:
            return Message.json_mess(2, 'token未通过验证', '')
        elif int(res) == 2:
            return Message.json_mess(1, 'token过期', '')

        payload_d = decode_token_bytes(payload)
        data = json.loads(payload_d.decode("utf8"))
        #判断调用此接口的user_id是否与token里的user_id相同
        user_id = data.get('user_id')
        log=auth.TabLog()
        log.user_id=user_id
        log.url=url
        log.create_time=datetime.now()
        log.type=0
        db.session.add(log)
        db.session.commit()
        # imei=data.get('imei')
        if uid != '':
            if str(uid) != str(user_id):
                return Message.json_mess(5, 'uid与token不匹配', '')
        if user_id != 0 :
            check_access=red_access_token.get(user_id)
        # else:
        #     check_access=red_access_token.get(imei)
        if check_access :
            if int(user_id)  > 0:
                key="user_"+str(user_id)
                #先取Redis里的用户信息，如果Redis里没有则从数据库取
                a = red_user_info.get(key)
                if a:
                    a = json.loads(a)
                    if int(a['status']) ==1 :
                        return Message.json_mess(14,"账户已经被封","")
                    if int(a['status']) ==2 :
                        return Message.json_mess(15,"账户不存在","")
                    role_id = a['role_id']
                else:
                    b=auth.TabUser.query.filter(auth.TabUser.id==user_id,auth.TabUser.status!=2).first()
                    if b:
                        if int(b.status)==1:
                            return Message.json_mess(14, "账户已经被封", "")
                        role_id = b.role_id
                    else:
                        return Message.json_mess(15,"账户不存在","")
            else:
                return Message.json_mess(15, "账户不存在", "")
            #超管的role_id为0，这边判断是否是超管
            if int(role_id) == 0:
                return Message.json_mess(0, '验证成功', '')
            #从Redis里取出此角色的所有权限，判断是否存在调用该接口的权限
            power=red_user_info.smembers("role_"+str(role_id))
            if power:
                for i in power:
                    i=ast.literal_eval(i)
                    if int(i['power_type'])==1:
                        if str(url) == str(i['power_url']):
                            return Message.json_mess(0, '验证成功', '')
            return Message.json_mess(13, '无此权限', '')
        else:
            return Message.json_mess(3, 'access_token签名验证错误', '')

    except Exception, e:
        print e
        current_app.logger.error(str(e))
        return Message.json_mess(16, '权限验证失败',"")



def header_check(head):
    try:
        funkiSystem = head['funkiSystem']
        check_sys=['iOSFunki','androidFunki','OPS','AgentPlatform','AndroidVRAPP','serverFunki']
        if funkiSystem in check_sys:
            if funkiSystem != 'serverFunki':
                softwareName = head['softwareName']
                imei = head['imei']
                session = head['session']
                system = head['system']
                deviceName = head['deviceName']
                deviceType = head['deviceType']
                ip = head['ip']
                geo = head['geo']
                isBreak = head['isBreak']
                version = head['funkiVersion']
                timestamp = time.time()
                res = {'funkiSystem': funkiSystem, 'softwareName': softwareName, 'imei': imei, 'session': session,
                       'system': system, 'deviceName': deviceName, 'deviceType': deviceType, 'ip': ip, 'geo': geo,
                       'isBreak': isBreak,'funkiVersion':version, 'timestamp': timestamp}
            else:
                ip = head['ip']
                timestamp = time.time()
                res={'funkiSystem': funkiSystem,'timestamp': timestamp,'ip':ip}

            Message.mq_send(config.mq_header['routing_key'], res, config.mq_header['user'],
                            config.mq_header['pwd'],
                            config.mq_header['url'], config.mq_header['exchange'], config.mq_header['exchange_type'])
            return True
        else:
            return False
    except Exception, e:
        current_app.logger.error(str(e))
        return False







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


# fontPath = "/usr/share/fonts/truetype/ttf-devanagari-fonts/"

# 获得随机四个字母
def getRandomChar():
    return [random.choice(string.letters) for _ in range(4)]




