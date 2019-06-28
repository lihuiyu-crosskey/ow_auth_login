# -*- coding: UTF-8 -*-
from app.models import cur,auth,db,red_user_info
from ..Messages.mess_handler import Message
from flask import current_app
import json




def get_username_by_id(ids):
    try:
        cur.reconnect()
        a=""
        for id in ids:
            a=a+","+str(id)
        a=a[1:]
        sql="SELECT id,name,real_name FROM tab_user where `status`!=2 and id in ("+a+")"
        data=cur.query(sql)
        return Message.json_mess(0,"查询成功",data)
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(10, '查询失败', '')
    finally:
        cur.close()


def delete_power_by_url_type(url,type):
    try:
        cur.reconnect()
        sql="select id from tab_power where power_url=%s and type=%s"
        data=cur.query(sql,url,str(type))
        for item in data:
            power_id=item['id']
            sql="delete from tab_role_power where power_id=%s"
            cur.execute(sql,power_id)
        sql="delete from tab_power where power_url=%s and type=%s"
        cur.execute(sql,url,str(type))
        return Message.json_mess(0,"删除成功","")
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(9, '删除失败', '')
    finally:
        cur.close()

def edit_pwoer_name_by_url_type(name,url,type):
    try:
        # cur.reconnect()
        # sql="update tab_power set power_name='%s' where power_url='%s' and type=%s"
        # cur.execute(sql,name,url,str(type))
        u=auth.TabPower.query.filter(auth.TabPower.power_url == url,auth.TabPower.type==type).first()
        u.power_name=name
        db.session.add(u)
        db.session.commit()
        return Message.json_mess(0,"编辑成功","")
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(8, '编辑失败', '')
    # finally:
    #     cur.close()


def add_power(name,url,type,role_id):
    try:
        check_name=auth.TabPower.query.filter(auth.TabPower.power_name==name).first()
        if check_name:
            return Message.json_mess(11,"权限名重复","")
        u=auth.TabPower()
        u.power_name=name
        u.power_url = url
        u.type=int(type)
        db.session.add(u)
        db.session.commit()

        a=auth.TabRolePower()
        a.role_id=role_id
        a.power_id=u.id
        db.session.add(a)
        db.session.commit()

        key = "role_" + str(role_id)
        res = {'power_id': u.id, 'power_url': url, 'power_name': u.power_name, 'power_type': u.type}
        red_user_info.sadd(key, json.dumps(res))

        return Message.json_mess(0,'添加成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')


def add_device(role_id,device_id):
    try:
        check_name=auth.TabPower.query.filter(auth.TabPower.power_url==device_id,auth.TabPower.type==4).first()

        sql="select * from tab_role_power where role_id=%s and power_id=%s limit 1"
        check=cur.get(sql,role_id,check_name.id)
        if check:
            return Message.json_mess(0, '添加成功', '')
        else:
            a=auth.TabRolePower()
            a.role_id=role_id
            a.power_id=check_name.id
            db.session.add(a)
            db.session.commit()

            key = "role_" + str(role_id)
            res = {'power_id': check_name.id, 'power_url': check_name.power_name, 'power_name': check_name.power_name, 'power_type': check_name.type}
            red_user_info.sadd(key, json.dumps(res))

        return Message.json_mess(0,'添加成功','')
    except Exception,e:
        current_app.logger.error(str(e))
        return Message.json_mess(7, '添加失败', '')