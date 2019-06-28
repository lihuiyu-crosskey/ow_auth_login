#coding=utf-8
#!/usr/bin/python

from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from manage import app
import config

http_server = HTTPServer(WSGIContainer(app))
http_server.listen(config.port)  #flask默认的端口
IOLoop.instance().start()