#-*- coding: UTF-8 -*-

from .. import blue
from flask import jsonify


class ErrorHandle(Exception):

    def __init__(self, message, code=None, data=''):
        Exception.__init__(self)
        self.message = message
        if code is not None:
            self.code = code
        self.data = data

    def to_dict(self):
        rv = dict()
        rv['data'] = self.data
        rv['message'] = self.message
        return rv


@blue.errorhandler(ErrorHandle)
def handle_error(error):
    response = error.to_dict()
    response['code'] = error.code
    return jsonify(response)


@blue.errorhandler(400)
def error_400(error):
    response = dict(code=400, message="请求参数错误", data='')
    return jsonify(response)