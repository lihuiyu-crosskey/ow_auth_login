# coding: utf-8
from manage import db


class TabMenu(db.Model):
    __tablename__ = 'tab_menu'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))

class TabMenuPower(db.Model):
    __tablename__ = 'tab_menu_power'

    id = db.Column(db.Integer, primary_key=True)
    menu_id = db.Column(db.Integer)
    power_id = db.Column(db.Integer)

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

class TabRolePower(db.Model):
    __tablename__ = 'tab_role_power'

    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer)
    power_id = db.Column(db.Integer)


class TabUser(db.Model):
    __tablename__ = 'tab_user'

    id = db.Column(db.BigInteger, primary_key=True)
    name = db.Column(db.String(255))
    real_name = db.Column(db.String(255))
    password = db.Column(db.String(255))
    salt = db.Column(db.String(255))
    mobile = db.Column(db.String(255))
    is_mobile = db.Column(db.Integer, server_default=db.FetchedValue())
    create_time = db.Column(db.DateTime)
    status = db.Column(db.Integer, server_default=db.FetchedValue())
    role_id = db.Column(db.Integer)


class TabLog(db.Model):
    __tablename__ = 'tab_log'

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.Integer)
    url =db.Column(db.String(255))
    create_time = db.Column(db.DateTime)
    type = db.Column(db.Integer)


class TabInterfaceCategory(db.Model):
    __tablename__ = 'tab_interface_category'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))

class TabInterfaceCategoryPower(db.Model):
    __tablename__ = 'tab_interface_category_power'

    id = db.Column(db.Integer, primary_key=True)
    interface_category_id = db.Column(db.Integer)
    power_id = db.Column(db.Integer)