#-*- coding: UTF-8 -*-
from flask import jsonify
import pika
import json

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