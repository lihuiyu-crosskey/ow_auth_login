# # -*- coding: UTF-8 -*-
# import pika
# import sys
# import json
# from datetime import datetime
# import os
# import thread,threading
# import Queue,time
#
#
#
# # check=os.getenv('FLASK_CONFIG')
# check='local'
# if check== 'local':
#     mq={'url': '192.168.1.239', 'user': 'guest', 'pwd': 'guest', 'routing_key': 'ff_watch',
#                     'exchange': 'ffDirect', 'exchange_type': 'direct'}
#
# elif check == 'dev':
#     mq = {'url': '10.42.29.194', 'user': 'guest', 'pwd': 'guest', 'routing_key': 'header_watch',
#           'exchange': 'headerDirect', 'exchange_type': 'direct'}
#
# x=1
#
#
#
#
#
# def rabbitmq_consumer():
#     user_pwd = pika.PlainCredentials(mq['user'], mq['pwd'])
#     print datetime.strftime(datetime.utcnow(), '%Y-%m-%d')
#     connection = pika.BlockingConnection(pika.ConnectionParameters(mq['url'], credentials=user_pwd))
#     channel = connection.channel()
#
#     channel.exchange_declare(exchange=mq['exchange'], exchange_type=mq['exchange_type'])
#
#     # queue_name = result.method.queue
#     severities = [mq['routing_key']]
#     if not severities:
#         sys.stderr.write("Usage: %s [info] [warning] [error]\n" % sys.argv[0])
#         sys.exit(1)
#
#     for severity in severities:
#         channel.queue_declare(queue=severity)
#         channel.queue_bind(exchange=mq['exchange'], queue=severity)
#         channel.basic_consume(callback, queue=severity, no_ack=True)
#     channel.start_consuming()
#
#
# def callback(ch, method, properties, body):
#     try:
#         print method.routing_key
#         print "body"+str(body)
#         if method.routing_key == mq['routing_key']:
#             res=json.loads(body)
#             if res['action'] == 'push':
#                 t = threading.Thread(target=push_stream,args=[res])
#                 t.start()
#                 pass
#             elif res['action'] == 'close':
#                 close_stream(res)
#             pass
#
#     except Exception,e:
#         print e
#         pass
#
# def push_stream(res):
#     try:
#         print res
#         ffmpeg_run(res['rtsp'], res['rtmp'])
#     except Exception,e:
#         print e
#         pass
#
#
# def close_stream(res):
#     try:
#         print res
#         kill_process_by_name(res['stream'])
#         print "success"
#     except Exception,e:
#         print e
#         pass
#
# def ffmpeg_run(rtsp,rtmp):
#     ffmpeg = "ffmpeg -i "+rtsp+"  -vcodec copy -acodec aac -ar 44100 -strict -2 -ac 1 -f flv -s 1280x720 -q 10 -f flv "+rtmp
#     print ffmpeg
#     ret=os.system(ffmpeg)
#     return ret
#
# def kill_process_by_name(name):
#     cmd = '''kill -9 `ps -aux|grep %s|awk '{print $2}'`
#         '''%(name)
#     ret=os.system(cmd)
#     return ret
#
#
#
#
#
#
#
# if  __name__ == '__main__':
#     rabbitmq_consumer()
