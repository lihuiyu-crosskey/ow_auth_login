# coding: utf-8
from . import db




class TabRole(db.Model):
    __tablename__ = 'tab_role'

    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(255))
    status = db.Column(db.Integer, server_default=db.FetchedValue())
    type = db.Column(db.Integer)

class TabPower(db.Model):
    __tablename__ = 'tab_power'

    id = db.Column(db.Integer, primary_key=True)
    power_name = db.Column(db.String(255))
    power_url=db.Column(db.String(255))
    type = db.Column(db.Integer)

class TabPowerGroup(db.Model):
    __tablename__ = 'tab_power_group'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))

class TabPowerPowerGroup(db.Model):
    __tablename__ = 'tab_power_group_power'

    id = db.Column(db.Integer, primary_key=True)
    power_group_id = db.Column(db.Integer)
    power_id = db.Column(db.Integer)

class TabRolePowerGroup(db.Model):
    __tablename__ = 'tab_role_power_group'

    id = db.Column(db.Integer, primary_key=True)
    power_group_id = db.Column(db.Integer)
    role_id = db.Column(db.Integer)



class TabUser(db.Model):
    __tablename__ = 'tab_user'

    id = db.Column(db.BigInteger, primary_key=True)
    nick_name = db.Column(db.String(255))
    password = db.Column(db.String(255))
    salt = db.Column(db.String(255))
    mobile = db.Column(db.String(255))
    create_time = db.Column(db.DateTime)
    status = db.Column(db.Integer, server_default=db.FetchedValue())
    role_id = db.Column(db.Integer)
    user_img = db.Column(db.String(255))
    is_real = db.Column(db.Integer)





