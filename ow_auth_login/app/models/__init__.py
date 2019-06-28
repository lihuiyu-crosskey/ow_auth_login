# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2016-
Author: QL Liu
"""
from flask_sqlalchemy import SQLAlchemy
import redis
import config
from flask_mail import Mail
import torndb



db = SQLAlchemy()

# mail=Mail()

red = redis.StrictRedis(host=config.redis_set['host'], port=config.redis_set['port'], db=config.redis_set['db'])
red_access_token = redis.StrictRedis(host=config.redis_access_token['host'], port=config.redis_access_token['port'], db=config.redis_access_token['db'])
red_refresh_token = redis.StrictRedis(host=config.redis_refresh_token['host'], port=config.redis_refresh_token['port'], db=config.redis_refresh_token['db'])
red_user_info = redis.StrictRedis(host=config.redis_user_info['host'], port=config.redis_user_info['port'], db=config.redis_user_info['db'])

cur=torndb.Connection(config.db_set['host']+":"+config.db_set['port'],config.db_set['db'],config.db_set['name'],config.db_set['password'],100,10)

