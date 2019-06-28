# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2017-5-1
Author: QL Liu
"""

import json
import os
import sys
from app.models import red


class RedisCache(object):
    """
    redis缓存公共类
    """
    def __init__(self):

        self.r =red

    def cache(self, name, ex=None, px=None):
        """
        设置新的一条redis的键值记录
        :param name:
        :param ex: 设置指定的到期时间(以秒为单位)。
        :param px: 设置指定的到期时间(以毫秒为单位)。
        :return:
        """
        def wrapper(func):
            def _wrapper(*args, **kwargs):
                try:
                    new_key = RedisCache.pack_key(args[0], name)
                    result = func(*args, **kwargs)
                    print "set_new_key:", new_key, args
                    value = json.dumps(result)
                    self.r.set(new_key, value, ex, px)
                except Exception, e:
                    raise "cache fail %s" % e
            return _wrapper
        return wrapper

    def get_cache(self, name):
        """
        根据键，从redis中获取一个对应记录
        :param name:
        :return:
        """
        def wrapper(func):
            def _wrapper(*args, **kwargs):
                new_key = RedisCache.pack_key(args[0], name)
                try:
                    value = self.r.get(new_key)
                except Exception, e:
                    raise "get_cache fail:%s" % e
                if not value:
                    result = func(*args, **kwargs)
                    if not result:
                        return result
                    json_value = json.dumps(result)
                    try:
                        self.r.set(new_key, json_value)
                    except Exception, e:
                        raise "set_cache fail：%s" % e
                    return result
                return json.loads(value)
            return _wrapper
        return wrapper

    def remove_cache(self, name):
        """
        删除某一键值
        :param name: 
        :return: 
        """
        def wrapper(func):
            def _wrapper(instance):
                try:
                    new_key = RedisCache.pack_key(instance, name)
                    self.r.delete(new_key)
                except Exception, e:
                    raise 'delete cache fail:%s !' % e
            return _wrapper
        return wrapper

    @staticmethod
    def pack_key(instance, name):
        """
        组装key
        :param instance: 
        :param name: 
        :return: 
        """
        absolute_path = os.path.abspath(sys.argv[0])
        class_name = instance.__class__.__name__
        new_key = ':'.join([absolute_path, class_name, name])
        return new_key




