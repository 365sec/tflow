# ecoding:utf-8
# run.py
'''
author:liulinghong
brief:prads
description:Packages Passive flow detection, call executable program, get standard output stream, parse standard output stream information format, parse data, and store into es
time:2019:9:27
'''
import datetime
import logging
import time
from subprocess import *
import threading
import re, sys
import hashlib
import os
import geoip2.database
import IPy
import timecycle
import firms
import netcard_name, IPdivide
from mongoclass import Mongoclass
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import esload
import json
import uuid
import traceback
import flow_counter
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
        self.flowcount = flow_counter.FlowCounter(self.cfg.get("passive_cfg"))
        print "ndpi init ..."

    def md5(self, str):
        m = hashlib.md5()
        m.update(str.encode("utf8"))
        return m.hexdigest()

    def capture(self, cfg):
        try:
            vlan = cfg.get("vlan","")
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
            logging.error(str(e))
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
            fc = threading.Thread(target=self.flowcount.save_data_in_db)
            fc.start()
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
                        #print line
                        temp_datalist =  re.split(r",(?![^(]*\))",line)
                        #print temp_datalist
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
                        flow["vlan"] = vlan
                        flow["classify"] = ""
                        try:
                            flow["last_seen"] = self.timestramp2time(flow["last_seen"])
                            flow["first_seen"] = self.timestramp2time(flow["first_seen"])
                        except Exception,e:
                            print e
                        host_name = flow.get("host_name", "")
                        if host_name:
                            if flow.get("detected_app_protocol") != "10" and flow.get("detected_app_protocol") != 10 and not IPdivide.ipcheck(host_name):
                                flow["domain"] = host_name
                                flow["host_name"] = ""
                        self.mac_manu_set(flow, flow.get("src_mac",""),"src",firms_lib_path)
                        self.mac_manu_set(flow, flow.get("dest_mac",""),"dest",firms_lib_path )
                        md5str = str(flow.get('host_a_name')) + str(flow.get(' host_a_port')) + str(
                            flow.get('host_b_name')) + str(flow.get('host_b_port'))
                        _id = self.md5(md5str)
                        dest_ip_geo = self.set_geo(str(flow.get("host_b_name")),geo_db)
                        src_ip_geo = self.set_geo(str(flow.get("host_a_name")),geo_db)
                        flow["dest_ip_geo"] = dest_ip_geo
                        flow["src_ip_geo"] = src_ip_geo
                        action = {
                            "_index": obj.index_name,
                            "_type": obj.index_type,
                            "_id": _id,
                            "_source": flow
                        }
                        #print action
                        try:
                            if IPdivide.ipcheck(flow.get("host_a_name")) and IPdivide.ipcheck(flow.get("host_b_name")) and action:
                                if ip_mode == 2:
                                    if IPdivide.ip_graph_check(flow.get("host_a_name"),IP_addresses) or IPdivide.ip_graph_check(
                                            flow.get("host_b_name"), IP_addresses):
                                        ACTIONS.append(action)
                                        if len(ACTIONS) > 50:
                                            self.mongo_data(ACTIONS=ACTIONS, cfg=cfg)
                                            obj.bulk_Index_Data(ACTIONS)
                                            self.outreach(ACTIONS,passive_cfg)
                                            # flowcount.read_flow_from_db()
                                            self.flow_counter_model(self.flowcount,ACTIONS)
                                            ACTIONS = []
                                elif ip_mode == 1:
                                    if IPdivide.is_internal_ip(flow.get("host_a_name")) or IPdivide.is_internal_ip(
                                            flow.get("host_b_name")):
                                        ACTIONS.append(action)
                                        if len(ACTIONS) > 50:
                                            self.mongo_data(ACTIONS=ACTIONS, cfg=cfg)
                                            obj.bulk_Index_Data(ACTIONS)
                                            self.outreach(ACTIONS, passive_cfg)
                                            self.flow_counter_model(self.flowcount, ACTIONS)
                                            ACTIONS = []
                                else:
                                    #print len(ACTIONS)
                                    ACTIONS.append(action)
                                    if len(ACTIONS) > 50:
                                        self.mongo_data(ACTIONS=ACTIONS, cfg=cfg)
                                        obj.bulk_Index_Data(ACTIONS)
                                        self.outreach(ACTIONS, passive_cfg)
                                        self.flow_counter_model(self.flowcount, ACTIONS)
                                        ACTIONS = []
                            else:
                                print "invaild ip format "
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
            country_code = "cn"
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
            "country_code": str(country_code).lower(),
            "latitude": latitude
        }


    def mac_manu_set(self,flow,mac,source,libpath):
        key = source + "_manufacturer"
        if mac:
            firm = firms.search_inlist(mac,libpath)
            if not firm:
                flow[key] = ""
            else:
                flow[key] = firm
        else:
            flow[key] = ""




    def mongo_data(self, ACTIONS, cfg):
        print "mongo in..."
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
        for action in ACTIONS:
            try:
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
                            else:
                                content["pc_name"] = ""
                            if os_name:
                                content["os_name"] = os_name
                            else:
                                content["os_name"] =""
                            if temp_collect.count() != 1:
                                mongo_client.delete(mongo_index, {"host_name": host_name})
                                mongo_client.insert_one(mongo_index, content)
                            else:
                                mongo_client.update_one(mongo_index, [{"host_name": host_name}, content])
                else:
                    return False
            except Exception, e:
                s = sys.exc_info()
                logging.debug(str(e))
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
                #w.join()
            # self.task["status"] = 2
        except Exception, e:
            logging.debug(str(e))
            self.task["success"] == False
            self.task["msg"] = str(e)
        # self.task["status"] = 2

    def set_time(self, time):
        self.accesstime = time

    def status(self):
        return self.work_status

    def stop(self):
        try:
            os.system("ps -ef|grep " + self.cfg.get("path") + " |grep -v grep|awk '{print $2}'|xargs kill -9")
            self.task["status"] = 2
            self.flowcount.status=0
            return True
        except Exception, e:
            logging.debug(str(e))
            return False


    def outreach(self,ACTIONS,passive_cfg):
        try:
            mongo_db = passive_cfg.get("mongo_db")
            if not mongo_db:
                return False
            mongo_path = mongo_db.get("path")
            mongo_port = mongo_db.get("port")
            mongo_index = str(mongo_db.get("index"))+"outreach"
            mongo_database = mongo_db.get("database")
            mongo_client = Mongoclass(mongo_path, int(mongo_port), mongo_database)
            if not mongo_client.get_state():
                return False
            for action in ACTIONS:
                flow  = action.get("_source",{})
                content={}
                domain = flow.get("domain","")
                detected_app_protocol = str(flow.get("detected_app_protocol",""))
                if domain and detected_app_protocol != '5':
                    similardoamin,domain_classtype = self.search_domain_classtype(domain)
                    if domain_classtype:
                        content["classtype"] = domain_classtype
                    else:
                        content["classtype"]=""
                    first_seen = flow.get("first_seen","")
                    last_seen = flow.get("last_seen", "")
                    dest_ip_geo =  flow.get("dest_ip_geo", {})
                    dst2src_bytes = float(flow.get("dst2src_bytes", ""))
                    src2dst_bytes = float(flow.get("src2dst_bytes", ""))
                    detected_protocol_name =  flow.get("detected_protocol_name", "")
                    country_code=dest_ip_geo.get("country_code", "")
                    if country_code !="cn":
                        domain_geo = 1
                    else:
                        domain_geo = 0
                    host_b_name =  flow.get("host_b_name", "")
                    host_a_name =  flow.get("host_a_name", "")
                    content["domain_geo"] = domain_geo
                    content["first_seen"]=first_seen
                    content["last_seen"] = last_seen
                    content["country_code"] = dest_ip_geo.get("country_code","")
                    content["country"] = dest_ip_geo.get("country","")
                    content["dst2src_bytes"] = dst2src_bytes
                    content["src2dst_bytes"] = src2dst_bytes
                    content["protocol_name"] = detected_protocol_name
                    content["domain"] = domain
                    content["source_ip"]=host_a_name
                    temp_collect = mongo_client.find(mongo_index, {"domain": domain,"source_ip":host_a_name})
                    if temp_collect.count() == 0:
                        content["dest_ip"] = [host_b_name]
                        content["times"] = 1
                        content["orid"] = str(uuid.uuid4()).decode("utf-8")
                        mongo_client.insert_one(mongo_index, content)
                    else:
                        source_ip_list=[]
                        for data in temp_collect:
                            dst2src_bytes += float(data.get("dst2src_bytes"))
                            src2dst_bytes += float(data.get("src2dst_bytes"))
                            source_ip_list = data.get("content",[])
                            source_ip_list.append(host_b_name)
                            times =int(data.get("times"))
                            times +=1
                        content["orid"] = data.get("orid")
                        content["times"] = times
                        content["dest_ip"] = source_ip_list
                        content["dst2src_bytes"] = dst2src_bytes
                        content["src2dst_bytes"] = src2dst_bytes
                        mongo_client.update_one(mongo_index, [{"domain": domain,"source_ip":host_a_name}, content])
        except Exception,e:
            msg = traceback.format_exc()
            print msg

    def search_domain_classtype(self,domain):
        import domain_class
        import difflib
        for key, value in domain_class.domain_classtype.items():
            similar = float(difflib.SequenceMatcher(None, key, domain).quick_ratio())
            if similar - float(0.80) >= 0:
                return key, value
        return "", ""


    def mongodb_size_(self,passive_cfg,collect_name):
        try:
            mongo_db = passive_cfg.get("mongo_db")
            if not mongo_db:
                return False
            mongo_path = mongo_db.get("path")
            mongo_port = mongo_db.get("port")
            mongo_index = str(mongo_db.get("index")) + collect_name
            mongo_database = mongo_db.get("database")
            mongo_client = Mongoclass(mongo_path, int(mongo_port), mongo_database)
            mongo_size = mongo_client.find(mongo_index,{}).count()
            if mongo_size > 10000:
                return False
            else:
                return True
        except Exception,e:
            msg = traceback.format_exc()
            print msg
            return False




    def timestramp2time(self,timestramp):
        timeArray = time.localtime(float(timestramp))
        otherStyleTime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
        return otherStyleTime


    def flow_counter_model(self,flowcount,ACTIONS):
        # mongo_db = passive_cfg.get("mongo_db")
        # if not mongo_db:
        #     return False
        # mongo_path = mongo_db.get("path")
        # mongo_port = mongo_db.get("port")
        # mongo_index = str(mongo_db.get("index")) + "flowcounter"
        # mongo_database = mongo_db.get("database")
        # mongo_client = Mongoclass(mongo_path, int(mongo_port), mongo_database)
        # if not mongo_client.get_state():
        #     return False
        s2c_bytes_all = 0
        c2s_bytes_all = 0
        s2c_packets_all=0
        c2s_packets_all=0
        for action in  ACTIONS:
            # src_content ={}
            # dest_content ={}
            flow  = action.get("_source",{})
            s_to_c_pkts = int(flow.get("src2dst_packets",0))
            s_to_c_bytes = float(flow.get("dst2src_bytes",0))
            # s_to_c_goodput_bytes = flow.get("s_to_c_goodput_bytes")
            c_to_s_pkts = int(flow.get("dst2src_packets",0))
            c_to_s_bytes = float(flow.get("src2dst_bytes",0))
            # c_to_s_goodput_bytes = flow.get("c_to_s_goodput_bytes")
            # s_to_c_goodput_bytes_radio = flow.get("s_to_c_goodput_bytes_radio")
            # c_to_s_goodput_bytes_radio = flow.get("c_to_s_goodput_bytes_radio")
            last_seen =flow.get("last_seen","")
            src_ip = flow.get("host_a_name","")
            dest_ip =flow.get("host_b_name","")
            print src_ip,"",dest_ip
            protocol_name = flow.get("detected_protocol_name","")
            event_name = flow.get("device_type","")
            vlan =flow.get("vlan","")
            s2c_bytes_all += s_to_c_bytes
            c2s_bytes_all += c_to_s_bytes
            s2c_packets_all += s_to_c_pkts
            c2s_packets_all += c_to_s_pkts
            # self.count_by_ip(mongo_client, mongo_index, src_ip, s_to_c_bytes, c_to_s_bytes)
            # self.count_by_ip(mongo_client, mongo_index, dest_ip, c_to_s_bytes,s_to_c_bytes)
            # self.count_by_tag(mongo_client,mongo_index,"ipaddr",src_ip,s_to_c_bytes,c_to_s_bytes,last_seen)
            # self.count_by_tag(mongo_client, mongo_index, "ipaddr", dest_ip,c_to_s_bytes ,s_to_c_bytes, last_seen)
            #"ipaddr","protocol","event","vlan"
            flowcount.get_data_from_flow("ipaddr",src_ip,s_to_c_bytes,c_to_s_bytes,timecycle.str_time_to_Mtime(last_seen),s_to_c_pkts,c_to_s_pkts)
            flowcount.get_data_from_flow("ipaddr", dest_ip, c_to_s_bytes ,s_to_c_bytes, timecycle.str_time_to_Mtime(last_seen),s_to_c_pkts,c_to_s_pkts)
            flowcount.get_data_from_flow("protocol",protocol_name, c_to_s_bytes ,s_to_c_bytes, timecycle.str_time_to_Mtime(last_seen),s_to_c_pkts,c_to_s_pkts)
            flowcount.get_data_from_flow("vlan", vlan, c_to_s_bytes, s_to_c_bytes, last_seen, timecycle.str_time_to_Mtime(last_seen),c_to_s_pkts)
            flowcount.get_data_from_flow("event", event_name, c_to_s_bytes, s_to_c_bytes, timecycle.str_time_to_Mtime(last_seen), s_to_c_pkts, c_to_s_pkts)

            flowcount.get_data_from_flow("last_seen", timecycle.str_time_to_day(last_seen), c_to_s_bytes, s_to_c_bytes, timecycle.str_time_to_Mtime(last_seen), s_to_c_pkts,c_to_s_pkts)
            print timecycle.str_time_to_day(last_seen),timecycle.str_time_to_Mtime(last_seen)
        flowcount.get_data_from_flow("all", "", c2s_bytes_all, s2c_bytes_all, timecycle.str_time_to_Mtime(last_seen), s2c_packets_all,c2s_packets_all)




        # self.all_bytes_counter(mongo_client,mongo_index,s2c_bytes_all,c2s_bytes_all)



    # def bytes_anlysis(self,s_to_c_pkts,s_to_c_bytes,s_to_c_goodput_bytes):
    #     s_to_c_goodput_bytes_radio = s_to_c_goodput_bytes/s_to_c_bytes

    def all_bytes_counter(self,mongo_client,mongo_index,s2c_bytes_all,c2s_bytes_all,last_seen):
        filter={
            "tag":"all",
        }
        all_bytes_data = mongo_client.find(mongo_index,filter)
        bytes_all = s2c_bytes_all+c2s_bytes_all,
        if all_bytes_data.count()<1:
            content = {
                "tag": "all",
                "bytes":bytes_all,
                "s2c_bytes_all":s2c_bytes_all,
                "c2s_bytes_all":c2s_bytes_all,
                "last_seen" : last_seen
            }
            mongo_client.insert_one(mongo_index,content)
        else:
            for content in all_bytes_data:
                s2c_bytes_all += float(content.get("s2c_bytes_all"))
                c2s_bytes_all += float(content.get("c2s_bytes_all"))
                bytes_all +=  float(content.get("bytes_all"))
            content = {
                "tag": "all",
                "bytes": bytes_all,
                "s2c_bytes_all": s2c_bytes_all,
                "c2s_bytes_all": c2s_bytes_all,
                "last_seen": last_seen
            }
            if all_bytes_data.count()>1:
                mongo_client.delete(mongo_index,{"tag": "all",})
            mongo_client.update(mongo_index,[{"tag": "all",},content])


    def count_by_tag(self,mongo_client,mongo_index,tag,object,s2c_bytes,c2s_bytes,last_seen):
        try:
            if tag not in ["ipaddr","protocol","event","vlan"]:
                return False
            filter = {
                "tag": tag,
                "object":object,
            }
            bytes_ipaddr = s2c_bytes+ c2s_bytes
            mongo_client_filter = mongo_client.find(mongo_index,filter)
            if mongo_client_filter.count() < 1:
                content = {
                    "tag": tag,
                    "object": object,
                    "bytes": bytes_ipaddr,
                    "s2c_bytes": s2c_bytes,
                    "c2s_bytes": c2s_bytes,
                    "last_seen": last_seen
                }
                mongo_client.insert_one(mongo_index, content)
            else:
                for content in mongo_client_filter:
                    s2c_bytes += float(content.get("s2c_bytes"))
                    c2s_bytes += float(content.get("c2s_bytes"))
                    bytes_ipaddr += float(content.get("bytes_ipaddr"))
                content = {
                    "tag": tag,
                    "object": object,
                    "bytes": bytes_ipaddr,
                    "s2c_bytes": s2c_bytes,
                    "c2s_bytes": c2s_bytes,
                    "last_seen": last_seen
                }
                if mongo_client_filter.count() > 1:
                    mongo_client.delete(mongo_index,{"tag": tag,"object": object})
                    mongo_client.insert_one(mongo_index, content)
                mongo_client.update(mongo_index, [{"tag": tag,"object": object}, content])
            return True
        except Exception,e:
            msg = traceback.format_exc()
            print msg
            return False

    # def count_by_app_protocol(self,mongo_client,mongo_index,detected_protocol_name,s2c_bytes,c2s_bytes,last_seen):
    #     filter = {
    #         "tag": "protocol",
    #         "object":detected_protocol_name,
    #     }
    #     bytes_ipaddr = s2c_bytes+ c2s_bytes
    #     count_by_protocol_name = mongo_client.find(mongo_index,filter)
    #     if count_by_protocol_name.count() < 1:
    #         content = {
    #             "tag": "protocol",
    #             "object": detected_protocol_name,
    #             "bytes": bytes_ipaddr,
    #             "s2c_bytes": s2c_bytes,
    #             "c2s_bytes": c2s_bytes,
    #             "last_seen": last_seen
    #         }
    #         mongo_client.insert_one(mongo_index, content)
    #     else:
    #         for content in count_by_protocol_name:
    #             s2c_bytes += float(content.get("s2c_bytes"))
    #             c2s_bytes += float(content.get("c2s_bytes"))
    #             bytes_ipaddr += float(content.get("bytes_ipaddr"))
    #         content = {
    #             "tag": "protocol",
    #             "object":detected_protocol_name,
    #             "bytes": bytes_ipaddr,
    #             "s2c_bytes": s2c_bytes,
    #             "c2s_bytes": c2s_bytes,
    #             "last_seen": last_seen
    #         }
    #         if count_by_protocol_name.count() > 1:
    #             mongo_client.delete(mongo_index,{ "tag": "protocol_name","object":detected_protocol_name})
    #         mongo_client.update(mongo_index, [{ "tag": "protocol_name","object":detected_protocol_name}, content])
    #
    #
    # def count_by_event_name(self,mongo_client,mongo_index,event_name,s2c_bytes,c2s_bytes,last_seen):
    #     filter = {
    #         "tag": "event",
    #         "object":event_name,
    #     }
    #     bytes_ipaddr = s2c_bytes+ c2s_bytes
    #     count_by_event_name = mongo_client.find(mongo_index,filter)
    #     if count_by_event_name.count() < 1:
    #         content = {
    #             "tag": "event",
    #             "object": event_name,
    #             "bytes": bytes_ipaddr,
    #             "s2c_bytes": s2c_bytes,
    #             "c2s_bytes": c2s_bytes,
    #             "last_seen": last_seen
    #         }
    #         mongo_client.insert_one(mongo_index, content)
    #     else:
    #         for content in count_by_event_name:
    #             s2c_bytes += float(content.get("s2c_bytes"))
    #             c2s_bytes += float(content.get("c2s_bytes"))
    #             bytes_ipaddr += float(content.get("bytes_ipaddr"))
    #         content = {
    #             "tag": "event",
    #             "object":event_name,
    #             "bytes": bytes_ipaddr,
    #             "s2c_bytes": s2c_bytes,
    #             "c2s_bytes": c2s_bytes,
    #             "last_seen": last_seen
    #         }
    #         if count_by_event_name.count() > 1:
    #             mongo_client.delete(mongo_index,{ "tag": "event","object":event_name})
    #         mongo_client.update(mongo_index, [{ "tag": "event","object":event_name}, content])
    #
    #
    # def count_by_vlan_name(self,mongo_client,mongo_index,tag,vlan_name,s2c_bytes,c2s_bytes,last_seen):
    #     filter = {
    #         "tag": "vlan",
    #         "object":vlan_name,
    #     }
    #     bytes_ipaddr = s2c_bytes+ c2s_bytes
    #     count_by_event_name = mongo_client.find(mongo_index,filter)
    #     if count_by_event_name.count() < 1:
    #         content = {
    #             "tag": "vlan",
    #             "object": vlan_name,
    #             "bytes": bytes_ipaddr,
    #             "s2c_bytes": s2c_bytes,
    #             "c2s_bytes": c2s_bytes,
    #             "last_seen": last_seen
    #         }
    #         mongo_client.insert_one(mongo_index, content)
    #     else:
    #         for content in count_by_event_name:
    #             s2c_bytes += float(content.get("s2c_bytes"))
    #             c2s_bytes += float(content.get("c2s_bytes"))
    #             bytes_ipaddr += float(content.get("bytes_ipaddr"))
    #         content = {
    #             "tag": "vlan",
    #             "object":vlan_name,
    #             "bytes": bytes_ipaddr,
    #             "s2c_bytes": s2c_bytes,
    #             "c2s_bytes": c2s_bytes,
    #             "last_seen": last_seen
    #         }
    #         if count_by_event_name.count() > 1:
    #             mongo_client.delete(mongo_index,{ "tag": "vlan","object":vlan_name})
    #         mongo_client.update(mongo_index, [{ "tag": "vlan","object":vlan_name}, content])



