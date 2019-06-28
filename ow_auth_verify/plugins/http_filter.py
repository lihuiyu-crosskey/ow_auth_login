# -*- coding:utf-8 -*-
from flask import jsonify
import json
import requests




def json_mess(code, message, data):
    if data == '':
        data = 'null'
    mess = {'code': code, 'message': message, 'data': data}
    return jsonify(mess)

def before_request(url,token):
    try:
        v=''
        url=url.split('/')
        for i, j in enumerate(url):
            if i>=3:
                v= v+"/"+j
        url = "http://35.164.1.183:7000/auth/power/verify"
        payload = {"token": token["token"], "url": v}
        response = requests.post(url, payload)
        res = response.text
        res = json.loads(res)
        if int(res['code'])==0:
            return "true"
        else:
            return jsonify(res)
    except Exception,e:
        print e
        return json_mess(111,'验证失败','')

def test(url):
    i=0
    while True:
        url = "http://35.164.1.183:7000/auth/power/verify"
        payload = {"token": "eyd0b2tlbl90eXBlJzogJ2FjY2VzcycsICdhbGcnOiAnU0hBMjU2JywgJ3R5cCc6ICdKV1QnfQ==.eyJleHBpcmVzIjogMTQ5NjQ2MzUwNS44NzY1OTQsICJ1c2VyX2lkIjogMjl9.48760b2bbb963aacf0681bf0e9caf409e44225ed4ce9ad779dd347887a2c9c9b", "url": "/live/open"}
        response = requests.post(url, payload)
        print response.text
        i = i - 1




