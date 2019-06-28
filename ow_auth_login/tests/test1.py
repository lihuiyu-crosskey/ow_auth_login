# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2016-
Author: QL Liu
"""
# import os
# print os.getenv('FLASK_CONFIG')
#
# class gg:
#     def __init__(self, name):
#         print "dd"
#         self.__name__ = name
#         print "s:", self.__name__
#
# gg('f')
# live = tab_live_room('123', '34', 'rt', '[1, 0]', 1, datetime.utcnow(), datetime.utcnow())
        # db.session.add(live)
        # db.session.commit()
        # print live.label
        # return jsonify(live.label)
from sqlalchemy import Column, String, create_engine, BigInteger, Integer, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

base = declarative_base()

class tab_live_room(base):
    __tablename__ = 'tab_live_room'
    id = Column(Integer, primary_key=True)
    theme = Column(String(100), unique=True)
    label = Column(String(100), unique=True)
    back_path = Column(String(100), unique=True)
    live_type = Column(String(30), unique=True)
    status = Column(BigInteger, unique=True)
    start_time = Column(DateTime)
    end_time = Column(DateTime)

engine = create_engine('mysql://root:12345678@192.168.100.201:3306/test')
DBsession = sessionmaker(bind=engine)
session = DBsession()
# 创建新User对象:
new_user = tab_live_room(theme='hh', label='jj', back_path='uu', live_type='[1, 0]', status=1, start_time=datetime.utcnow(),end_time=datetime.utcnow())
# 添加到session:
session.add(new_user)
# 提交即保存到数据库:
session.commit()
# 关闭session:
session.close()