# -*- coding:utf-8 -*-
from flask import jsonify
import json
import requests




def json_mess(code, message, data):
    mess = {'code': code, 'message': message, 'data': data}
    return jsonify(mess)

def before_request(request_url,url,uid,header):
    try:
        v=''
        url=url.split('/')
        for i, j in enumerate(url):
            if i>=3:
                v= v+"/"+j
        headers = {
            'content-type': "application/json"
        }
        # funkiSystem = header['funkiSystem']
        # if funkiSystem != 'serverFunki':
        #     softwareName = header['softwareName']
        #     imei = header['imei']
        #     session = header['session']
        #     system = header['system']
        #     deviceName = header['deviceName']
        #     deviceType = header['deviceType']
        #     ip = header['ip']
        #     geo = header['geo']
        #     isBreak = header['isBreak']
        #     version=header['funkiVersion']
        #     token=header['token']
        #     res = {'funkiSystem': funkiSystem, 'softwareName': softwareName, 'imei': imei, 'session': session,
        #            'system': system, 'deviceName': deviceName, 'deviceType': deviceType, 'ip': ip, 'geo': geo,
        #            'isBreak': isBreak, 'funkiVersion':version,'token': token}
        # else:
        #     ip = header['ip']
        #
        token=header['access_token']
        res={"token":token}
        payload = {"header": res, "url": v,"uid":uid}
        response = requests.post(request_url,json.dumps(payload),headers=headers)
        res = response.text
        res = json.loads(res)
        if int(res['code'])==0:
            return "true"
        else:
            return jsonify(res)
    except Exception,e:
        print e
        return json_mess(55,'header参数错误','')




