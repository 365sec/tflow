# ecoding:utf-8
# run.py
'''
author:liulinghong
brief:prads
description:Packages Passive flow detection, call executable program, get standard output stream, parse standard output stream information format, parse data, and store into es
time:2019:9:27
'''
import datetime
import time
from subprocess import *
import threading
import re, sys
import hashlib
import os
import geoip2.database
import IPy
import firms
import netcard_name, IPdivide
from mongoclass import Mongoclass

import sys

reload(sys)
sys.setdefaultencoding('utf-8')

# from mongo_config import mongo_settings as settings
# from pymongo import MongoClient
#
# settings = {
#   "ip":'172.16.39.15',   #ip
#   "port":27017,
#   "db_name" : "mydb",
#   "set_name" : "prads"
# }
# conn = MongoClient(settings["ip"], settings["port"])
# db = conn[settings["db_name"]]
# my_set = db[settings["set_name"]]
import esload
import json


class Passiveasset:
    def __init__(self, task):
        self.category_map = self.category_map = {
            "25": "娱乐",
            "26": "娱乐",
            "27": "娱乐",
            "28": "其他",
            "29": "数据管理",
            "1": "流媒体服务器",
            "0": "未知",
            "3": "邮件系统",
            "2": "虚拟专用网络",
            "5": "Web",
            "4": "数据管理",
            "7": "数据管理",
            "6": "社交网络",
            "9": "社交网络",
            "8": "娱乐",
            "99": "挖矿",
            "11": "数据库",
            "10": "娱乐",
            "13": "云平台",
            "12": "远程访问",
            "15": "其他",
            "14": "广播",
            "17": "VOIP",
            "16": "远程过程调用",
            "19": "其他系统软件",
            "18": "其他系统软件",
            "100": "恶意软件",
            "101": "娱乐",
            "105": "其他安全产品"
        }
        self.Ready = 0
        self.Running = 1
        self.Termination = 2
        self.Error_state = 3
        self.work_status = 0
        self.server_path = ""
        self.task = task
        self.cfg = self.task.get("cfg")
        print "ndpi init ..."

    def md5(self, str):
        m = hashlib.md5()
        m.update(str.encode("utf8"))
        return m.hexdigest()

    def capture(self, cfg):

        try:
            vlan = cfg.get("vlan")
            pcap = cfg.get("pcap")
            path = cfg.get("path")
            passive_cfg = cfg.get("passive_cfg")
            index_name = passive_cfg.get("es_passive").get("index_name")
            index_type = passive_cfg.get("es_passive").get("index_type")
            es_path = passive_cfg.get("es_passive").get("path")
            access_time = cfg.get("access_time", 20)
            temp_flow = passive_cfg.get("temp_flow", "temp_flow.csv")
            passive_hz = str(passive_cfg.get("ndpi_hz", "5"))
            task_type = cfg.get("task_type")
            IP_addresses = cfg.get("ipaddresses")
            ip_mode = cfg.get("ip_mode")
            geo_db = passive_cfg.get("geo_db")
            keys_list_paths=passive_cfg.get("keys_list_paths")
            head_key = json.loads(open(keys_list_paths,"r").read())
            firms_lib_path  = passive_cfg.get("mac_firms")
            if "vlan" in task_type:
                command = path + " -i " + vlan + " -C " + temp_flow + " -m " + passive_hz + " -s " + str(
                    access_time) + " -q 2>&1 "
            else:
                command = path + " -i " + pcap + " -C " + temp_flow + " -m " + passive_hz + " -s " + str(
                    access_time) + " -q 2>&1 "
                ip_mode = 3
            print "command: " + command
            p = Popen(command, shell=True, stdin=PIPE, stdout=PIPE)
            print "启动成功"
            self.work_status = self.Running
        except Exception, e:
            print e
            self.task["status"] = 2
            return 0

        '''
        path:服务程序启动路径
        vlan:被监听的网卡
        temp_flow:数据日志
        passive_hz:服务程序推送结果频率
        access_time:服务启动时间
        '''
        obj = esload.ElasticObj(index_name, index_type, ip=es_path)

        if self.work_status == self.Running:
            print 'running1'
            ACTIONS = []
            count = 0
            for line in p.stdout:
                if not line:
                    count += 1
                    time.sleep(1)
                if count >= 50:
                    count = 0
                    obj.bulk_Index_Data(ACTIONS)
                line = line.strip()
                # print  "-->",line
                if ',' in line:
                    try:
                        line = line.encode('utf-8')
                        temp_datalist = line.split(',')
                        if len(head_key) > len(temp_datalist):
                            continue
                        flow = {}
                        for index in range(0, len(head_key)):
                            flow[head_key[index]] = temp_datalist[index]
                        for key in flow.keys():
                            if '.' in key:
                                flow.update({key.replace('.', '_'): flow.pop(key)})
                        category_id = flow.get("protocol_category", "")
                        try:
                            category_name = self.category_map[str(category_id)].decode('utf-8')
                        except Exception, e:
                            category_name = "未知".decode('utf-8')

                        utc_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0800")
                        flow["timestamp"] = utc_time
                        flow["device_type"] = category_name
                        flow["packets"] = int(flow.get("src2dst_packets", 0)) + int(flow.get("dst2src_packets", 0))
                        flow["bytes"] = int(flow.get("src2dst_bytes", 0)) + int(flow.get("dst2src_bytes", 0))
                        flow["category"] = "软件".decode('utf-8')
                        flow["classify"] = ""
                        self.mac_manu_set(flow, flow.get("src_mac",""),"src",firms_lib_path)
                        self.mac_manu_set(flow, flow.get("dest_mac",""),"dest",firms_lib_path )
                        print flow["src_manufacturer"]
                        md5str = str(flow.get('host_a_name')) + str(flow.get(' host_a_port')) + str(
                            flow.get('host_b_name')) + str(flow.get('host_b_port'))
                        _id = self.md5(md5str)
                        dest_ip_geo = self.set_geo(str(flow.get("host_b_name")),geo_db)
                        flow["dest_ip_geo"] = dest_ip_geo
                        action = {
                            "_index": obj.index_name,
                            "_type": obj.index_type,
                            "_id": _id,
                            "_source": flow
                        }
                        #print action,'\n',ip_mode
                        try:
                            if IPdivide.ipcheck(flow.get("host_a_name")) and IPdivide.ipcheck(flow.get("host_b_name")) and action:
                                if ip_mode == 2:
                                    if IPdivide.ip_graph_check(flow.get("host_a_name"),IP_addresses) or IPdivide.ip_graph_check(
                                            flow.get("host_b_name"), IP_addresses):
                                        ACTIONS.append(action)
                                        if len(ACTIONS) > 50:
                                            self.mongo_data(ACTIONS=ACTIONS, cfg=cfg)
                                            obj.bulk_Index_Data(ACTIONS)
                                            ACTIONS = []
                                elif ip_mode == 1:
                                    if IPdivide.is_internal_ip(flow.get("host_a_name")) or IPdivide.is_internal_ip(
                                            flow.get("host_b_name")):
                                        ACTIONS.append(action)
                                        if len(ACTIONS) > 50:
                                            self.mongo_data(ACTIONS=ACTIONS, cfg=cfg)
                                            obj.bulk_Index_Data(ACTIONS)
                                            ACTIONS = []
                                else:
                                    print len(ACTIONS)
                                    ACTIONS.append(action)
                                    if len(ACTIONS) > 50:
                                        self.mongo_data(ACTIONS=ACTIONS, cfg=cfg)
                                        obj.bulk_Index_Data(ACTIONS)
                                        ACTIONS = []
                                    # print action
                        except Exception, e:
                            print 5, e
                            s = sys.exc_info()
                            print "Error '%s' happened on line %d" % (s[1], s[2].tb_lineno)

                    except Exception, e:
                        # print 'code:',6,e
                        s = sys.exc_info()
                        print "Error '%s' happened on line %d" % (s[1], s[2].tb_lineno)

    def set_geo(self,dest_ip,geo_db):
        if IPdivide.is_internal_ip(dest_ip):
            intranet = "内网".decode('utf-8')
            country = "中国".decode('utf-8')
            province = ""
            city = ""
            latitude = ""
            longitude = ""
            country_code = ""
        else:
            intranet = "外网".decode('utf-8')
            country = ""
            province = ""
            city = ""
            latitude = ""
            longitude = ""
            country_code = ""
            try:
                reader = geoip2.database.Reader(geo_db)
                try:
                    response = reader.city(dest_ip)
                    country = response.country.names.get('zh-CN', u'')
                    province = response.subdivisions.most_specific.names.get('zh-CN', u'')
                    city = response.city.names.get('zh-CN', u'')
                    latitude = response.location.latitude
                    longitude = response.location.longitude
                    country_code = response.country.iso_code
                except Exception, e:
                    pass
                if not country:
                    try:
                        response = reader.city(dest_ip)
                        country = response.country.names.get('en', '')
                        province = response.subdivisions.most_specific.names.get('en', '')
                        city = response.city.names.get('en', '')
                        latitude = response.location.latitude
                        longitude = response.location.longitude
                        country_code = response.country.iso_code
                    except:
                        pass
            except Exception, e:
                s = sys.exc_info()
                print "Error '%s' happened on line %d" % (s[1], s[2].tb_lineno)


        return {
            "intranet": intranet,
            "province": province,
            "city": city,
            "country": country,
            "longitude": longitude,
            "country_code": country_code,
            "latitude": latitude
        }


    def mac_manu_set(self,flow,mac,source,libpath):
        key = source + "_manufacturer"
        if mac:
            firm = firms.search_inlist(mac,libpath)
            if not firm:
                flow[key] = ("", "")
            else:
                flow[key] = firm
        else:
            flow[key] = ""




    def mongo_data(self, ACTIONS, cfg):
        print "mongo in..."
        for action in ACTIONS:
            try:
                passive_cfg = cfg.get("passive_cfg")
                # print passive_cfg
                mongo_db = passive_cfg.get("mongo_db")
                if not mongo_db:
                    return False
                mongo_path = mongo_db.get("path")
                mongo_port = mongo_db.get("port")
                mongo_index = mongo_db.get("index")
                mongo_database = mongo_db.get("database")
                mongo_client = Mongoclass(mongo_path, int(mongo_port), mongo_database)
                if not mongo_client.get_state():
                    return False
                flow = action.get("_source")
                if flow:
                    detected_protocol_name = flow.get("detected_protocol_name")
                    host_a_name = flow.get("host_a_name", "")
                    host_b_name = flow.get("host_b_name", "")
                    pc_name = flow.get("host_name", "")
                    os_name = flow.get("os", "")
                    mac = flow.get("src_mac", "")
                    src_manufacturer = flow.get("src_manufacturer","")
                    host_list = []
                    host_list.append(host_a_name)
                    # host_list.append(host_b_name)
                    for host_name in host_list:
                        if not IPdivide.is_internal_ip(host_a_name):
                            continue
                        temp_collect = mongo_client.find("passive_flow", {"host_name": host_name, })
                        if temp_collect.count() == 0:
                            content = {
                                "tags": [detected_protocol_name],
                                "host_name": host_name,
                                "pc_name": pc_name,
                                "os_name": os_name,
                                "mac": mac,
                                "src_manufacturer":src_manufacturer
                            }
                            mongo_client.insert_one(mongo_index, content)
                        else:
                            tags = [detected_protocol_name]
                            for temp in temp_collect:
                                tag = temp.get("tags")
                                if isinstance(tag, list):
                                    tags.extend(tag)
                                    tags = list(set(tags))
                            content = {
                                "host_name": host_name,
                                "tags": tags
                            }
                            if pc_name:
                                content["pc_name"] = pc_name
                            if (os_name and "windows" in os_name.lower()) or (
                                    os_name and "windows" not in temp_collect[0].get("os_name", "").lower()):
                                content["os_name"] = os_name

                            if temp_collect.count() != 1:
                                mongo_client.delete(mongo_index, {"host_name": host_name})
                                mongo_client.insert_one(mongo_index, content)
                            else:
                                mongo_client.update_one(mongo_index, [{"host_name": host_name}, content])
                else:
                    return False
            except Exception, e:
                s = sys.exc_info()
                print "Error '%s' happened on line %d" % (s[1], s[2].tb_lineno)

    def cfg_check(self, cfg):
        try:
            vlan = cfg.get("vlan")
            pcap = cfg.get("pcap")
            path = cfg.get("path")
            passive_cfg = cfg.get("passive_cfg")
            index_name = passive_cfg.get("es_passive").get("index_name")
            index_type = passive_cfg.get("es_passive").get("index_type")
            es_path = passive_cfg.get("es_passive").get("path")
            type = self.cfg.get("task_type")
            if not index_name:
                return False
            if not index_type:
                return False
            if not es_path:
                return False
            if "vlan" in type:
                if vlan not in netcard_name.get_netcard():
                    return False
            else:
                if not os.path.exists(str(pcap)):
                    return False
                else:
                    filnenmae, filetype = os.path.splitext(pcap)
                    if filetype not in ['.pcap', '.pcapng']:
                        return False
            if not os.path.exists(path):
                return False
            return True
        except Exception, e:
            print e
            return False

    def run(self):
        try:
            if self.cfg_check(self.cfg):
                self.server_path = self.cfg.get("path")
                self.work_status = self.Ready  # 设置ready状态
                access_time = self.cfg.get("access_time", 3600)
                self.set_time(access_time)  # 设置启动时长
            else:
                self.work_status = self.Error_state
            if self.work_status == self.Ready:
                w = threading.Thread(target=self.capture, args=[self.cfg])
                w.start()  # 创建任务线程，在ready状态下启动
                w.join()
            self.task["status"] = 2
        except Exception, e:
            print e
            self.task["success"] == False
            self.task["msg"] = str(e)
        self.task["status"] = 2

    def set_time(self, time):
        self.accesstime = time

    def status(self):
        return self.work_status

    def stop(self):
        try:
            os.system("ps -ef|grep " + self.cfg.get("path") + " |grep -v grep|awk '{print $2}'|xargs kill -9")
            self.task["status"] = 2
            return True
        except Exception, e:
            return False


