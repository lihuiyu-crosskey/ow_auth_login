#-*- coding: UTF-8 -*-
from app.services import auth_web_ser
from flask import jsonify, request, redirect, make_response,Flask
from config import blue,beforeLogin
from ..Messages.mess_handler import Message
from datetime import datetime
from flask import current_app




