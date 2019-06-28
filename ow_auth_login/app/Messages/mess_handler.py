#-*- coding: UTF-8 -*-
from flask import jsonify
import pika
import json
import requests

class Message(object):
    @staticmethod
    def json_mess(code,message,data):
        mess={'code':code,'message':message,'data':data}
        return jsonify(mess)

    @staticmethod
    def mq_send(routing_key, message, user, pwd, url, exchange, exchange_type):
        """
        direct方式的生产者
        :param routing_key:
        :param message:
        :return:
        """
        credentials = pika.PlainCredentials(user, pwd)
        connection = pika.BlockingConnection(pika.ConnectionParameters(url, credentials=credentials))
        channel = connection.channel()
        channel.exchange_declare(exchange=exchange, exchange_type=exchange_type)
        channel.queue_declare(queue=routing_key)
        channel.queue_bind(queue=routing_key, exchange=exchange)
        channel.basic_publish(exchange=exchange, routing_key=routing_key, body=json.dumps(message))
        # print "dd"
        connection.close()

    @staticmethod
    def post_json_request(url, post_data, header_type):
        error = None
        if int(header_type) == 1:
            headers = {
                'content-type': "application/x-www-form-urlencoded"
            }
        elif int(header_type) == 2:
            headers = {
                'content-type': "application/json"
            }
            post_data = json.dumps(post_data)
        try:
            response = requests.post(url, data=post_data, headers=headers)
            print response
        except requests.exceptions.ConnectTimeout:
            # return "time out"
            return error
        except requests.exceptions.ConnectionError:
            return error
        res_data = response.text
        return res_data