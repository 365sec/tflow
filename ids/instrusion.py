# ecoding:utf-8
import hashlib
import json
import os
import re
import threading
import traceback

import IPy
import geoip2.database
import redis
from flow_assets import logcfg as flow_log
from flow_assets.tools import esload
from flow_assets.tools import ipdivide
from flow_assets.tools import mongoclass

# import logging
import blacks
import netcard_name


class IdsInstrusion:
    def __init__(self, task):
        self.task = task
        # self.cfg = cfg
        self.Ready = 0
        self.Running = 1
        self.Termination = 2
        self.Error_state = 3
        self.work_status = 0
        self.cfg = self.task.get("cfg")
        flow_log.logger.debug("类IdsInstrusion初始化成功...")

    def md5(self, str):
        m = hashlib.md5()
        m.update(str.encode("utf8"))
        return m.hexdigest()

    # def utc_to_local(utc_time_str, utc_format='%Y-%m-%dT%H:%M:%S.%f+0800'):
    #     local_tz = pytz.timezone('Asia/Chongqing')
    #     local_format = "%Y-%m-%d %H:%M:%S"
    #     utc_dt = datetime.datetime.strptime(utc_time_str, utc_format)
    #     local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
    #     time_str = local_dt.strftime(local_format)
    #     return time_str

    def mongo_data(self, ACTIONS, cfg):
        '''

        :param action:
        :param cfg:
        :return:
        '''
        for action in ACTIONS:
            try:
                instrusion_cfg = cfg.get("instrusion_cfg")
                mongo_db = instrusion_cfg.get("mongo_db")
                if not mongo_db:
                    return False
                mongo_path = mongo_db.get("path")
                mongo_port = mongo_db.get("port")
                mongo_database = mongo_db.get("database")
                mongo_index = mongo_db.get("index")
                mongo_index_sign = str(mongo_db.get("index")) + "sign"
                mongo_index_event = str(mongo_db.get("index")) + "event"
                mongo_client = mongoclass.Mongoclass(mongo_path, int(mongo_port), mongo_database)
                if not mongo_client.get_state():
                    flow_log.logger.debug("mongo 数据库连接失败")
                    return False
                if not mongo_client.mongodb_size_count(mongo_index, {}):
                    flow_log.logger.debug("mongo 数据库数据量限制")
                    return False
                event = action.get("_source")
                if event:
                    alert = event.get("alert")
                    dest_ip = event.get("dest_ip")
                    src_ip = event.get("src_ip")
                    timestamp = event.get("timestamp")
                    # print timestamp
                    try:
                        if alert:
                            signature = alert.get("signature")
                        if signature:
                            temp = mongo_client.find(mongo_index_sign, {"signature": signature})
                            if temp.count() == 0:
                                content = {
                                    "host_names": [src_ip, dest_ip],
                                    "signature": signature,
                                }
                                mongo_client.insert_one(mongo_index_sign, content)
                            else:
                                host_names = [src_ip, dest_ip]
                                for row in temp:
                                    host = row.get("host_names")
                                    if isinstance(host, list):
                                        host_names.extend(host)
                                        host_names = list(set(host_names))
                                content = {
                                    "host_names": host_names,
                                    "signature": signature
                                }
                                if temp.count() > 1:
                                    mongo_client.delete(mongo_index_sign, {"signature": signature})
                                    mongo_client.insert_one(mongo_index_sign, content)
                                else:
                                    mongo_client.update_one(mongo_index_sign, [{"signature": signature}, content])

                    except Exception, e:
                        msg = traceback.format_exc()
                        flow_log.logger.debug(msg)
                    try:
                        host_list = []
                        host_list.append(src_ip)
                        host_list.append(dest_ip)
                        for host_name in host_list:
                            temp_collect = mongo_client.find(mongo_index, {"host_name": host_name})
                            if temp_collect.count() == 0:
                                content = {
                                    "timestamp": timestamp,
                                    "times": 1,
                                    "host_name": host_name,
                                }
                                mongo_client.insert_one(mongo_index, content)
                            else:
                                times = 1
                                for temp in temp_collect:
                                    temp_times = int(temp.get("times"))
                                    times += temp_times
                                content = {
                                    "timestamp": timestamp,
                                    "times": times,
                                    "host_name": host_name,
                                }
                                if temp_collect.count() > 1:
                                    mongo_client.delete(mongo_index, {"host_name": host_name})
                                    mongo_client.insert_one(mongo_index, content)
                                else:
                                    mongo_client.update_one(mongo_index, [{"host_name": host_name}, content])
                    except Exception, e:
                        msg = traceback.format_exc()
                        flow_log.logger.debug(msg)

                    try:
                        temp_collect = mongo_client.find(mongo_index_event, {"signature": signature})
                        if temp_collect.count() == 0:
                            content = {
                                "timestamp": timestamp,
                                "times": 1,
                                "signature": signature,
                            }
                            mongo_client.insert_one(mongo_index_event, content)
                        else:
                            times = 1
                            for temp in temp_collect:
                                temp_times = int(temp.get("times"))
                                times += temp_times
                            content = {
                                "timestamp": timestamp,
                                "times": times,
                                "signature": signature,
                            }
                            if temp_collect.count() > 1:
                                mongo_client.delete(mongo_index_event, {"signature": signature})
                                mongo_client.insert_one(mongo_index_event, content)
                            else:
                                mongo_client.update_one(mongo_index_event, [{"signature": signature}, content])
                    except Exception, e:
                        msg = traceback.format_exc()
                        flow_log.logger.debug(msg)

                else:
                    return False
            except Exception, e:
                msg = traceback.format_exc()
                flow_log.logger.debug(msg)

    def ipcheck(self, ip_addrr):
        try:
            if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                        ip_addrr):
                return True
            else:
                return False
        except:
            return False

    def ip_addrs_check(self, ip, ip_addrs):
        return ip in IPy.IP(ip_addrs)

    def redis_data(self, cfg):
        try:
            ACTIONS = []
            flow_log.logger.debug("正在从redis获取数据")
            pool = redis.ConnectionPool(host='127.0.0.1', port=6379)
            r = redis.Redis(connection_pool=pool)
            instrusion_cfg = cfg.get("instrusion_cfg")
            es_instrusion = instrusion_cfg.get("es_instrusion")
            es_flow = instrusion_cfg.get("es_flow")
            obj = esload.ElasticObj(es_instrusion.get("index_name"), es_instrusion.get("index_type"),
                                    es_instrusion.get("path"))
            flow = esload.ElasticObj(es_flow.get("index_name"), es_flow.get("index_type"), es_flow.get("path"))
            IP_addresses = cfg.get("ipaddresses")
            # print cfg
            ip_mode = cfg.get("ip_mode")
            geo_db = instrusion_cfg.get("geo_db")
            classtype_cfg_path = instrusion_cfg.get("classtype_cfg_path", "")
            # classtype_cfg_path = "classtype.json"
            classtype_dict = json.loads(open(classtype_cfg_path).read())
            while True:
                try:
                    if self.task["status"] == 2:
                        break
                    try:
                        ori_data = r.lpop("suricata")
                        if ori_data:
                            data1 = json.loads(json.dumps(ori_data).encode('utf-8'))
                            data = json.loads(data1)
                        else:
                            data = ''
                    except Exception, e:
                        data = ''
                    if not data:
                        continue
                    event_type = data.get("event_type")
                    dest_ip = str(data.get("dest_ip"))
                    src_ip = str(data.get("src_ip"))
                    data["dest_ip_geo"] = self.area_info(dest_ip, geo_db)
                    data["src_ip_geo"] = self.area_info(src_ip, geo_db)
                    if event_type == 'alert':
                        classname = data.get("alert", {}).get("category", "")
                        classtype = classtype_dict.get(classname, {})
                        data["alert"]["category"] = classtype.get("classname", "其他".decode())
                        data["alert"]["behavior"] = classtype.get("behavior", "尝试".decode())
                        data["alert"]["origin"] = classtype.get("origin", "基础防御".decode())
                        severity = data["alert"]["severity"]
                        if severity == "1" or severity == 1:
                            data["alert"]["severity"] = "高危"
                        elif severity == "2" or severity == 2:
                            data["alert"]["severity"] = "中危"
                        else:
                            data["alert"]["severity"] = "低危"
                        action = {
                            "_index": obj.index_name,
                            "_type": obj.index_type,
                            "_source": data
                        }
                        if ip_mode == 2:
                            if self.ip_addrs_check(data.get("dest_ip"), IP_addresses) or self.ip_addrs_check(
                                    data.get("src_ip"), IP_addresses):
                                ACTIONS.append(action)
                                self.mongo_data(ACTIONS=ACTIONS, cfg=cfg)
                                obj.bulk_Index_Data(ACTIONS)
                                ACTIONS = []
                        elif ip_mode == 1:
                            if ipdivide.is_internal_ip(data.get("dest_ip")) or ipdivide.is_internal_ip(
                                    data.get("src_ip")):
                                ACTIONS.append(action)
                                self.mongo_data(ACTIONS=ACTIONS, cfg=cfg)
                                obj.bulk_Index_Data(ACTIONS)
                                ACTIONS = []
                        else:
                            ACTIONS.append(action)
                            self.mongo_data(ACTIONS=ACTIONS, cfg=cfg)
                            obj.bulk_Index_Data(ACTIONS)
                            ACTIONS = []
                    else:
                        flow_log.logger.debug("其他类型数据:" + event_type)

                    # else:
                    #     md5str = str(data.get('dest_ip')) + str(data.get('dest_port')) + str(
                    #         data.get('src_ip')) + str(data.get('src_port'))
                    #     _id = self.md5(md5str)
                    #     action = {
                    #         "_index": flow.index_name,
                    #         "_type": flow.index_type,
                    #         "_source": data
                    #     }
                    #     ACTIONS_flow.append(action)
                    #     if len(ACTIONS_flow)>200:
                    #         flow.bulk_Index_Data(ACTIONS_flow)
                except Exception, e:
                    msg = traceback.format_exc()
                    flow_log.logger.error(msg)
        except Exception, e:
            msg = traceback.format_exc()
            flow_log.logger.error(msg)

    def cfg_check(self):
        try:
            vlan = self.cfg.get("vlan")
            pcap = self.cfg.get("pcap")
            instrusion_cfg = self.cfg.get("instrusion_cfg")
            es_index_name = instrusion_cfg.get("es_instrusion", {}).get("index_name", "")
            es_index_type = instrusion_cfg.get("es_instrusion", {}).get("index_type", "")
            es_path = instrusion_cfg.get("es_instrusion", {}).get("path", "")
            es_port = instrusion_cfg.get("es_instrusion", {}).get("port", "")
            if not es_index_name or not es_index_type or not es_path or not es_port:
                flow_log.logger.debug("instrusion es_instrusion 配置有误，请核验...")
                return False

            mongo_db_cfg = instrusion_cfg.get("mongo_db", {})
            mongo_db_path = mongo_db_cfg.get("path", "")
            mongo_db_path_index = mongo_db_cfg.get("path", "")
            mongo_db_path_port = mongo_db_cfg.get("port", "")
            mongo_db_path_database = mongo_db_cfg.get("database", "")
            if not mongo_db_path or not mongo_db_path_index or not mongo_db_path_port or not mongo_db_path_database:
                flow_log.logger.debug("instrusion mongodb 配置有误，请核验...")
                return False
            geo_db_path = instrusion_cfg.get("geo_db", "")
            if not os.path.exists(geo_db_path):
                flow_log.logger.debug("instrusion geo_db 配置有误，请核验...")
                return False
            user_defined_blackip_path = instrusion_cfg.get("user_defined_blackip_path", "")
            if not os.path.exists(user_defined_blackip_path):
                flow_log.logger.debug("instrusion user_defined_blackip_path 配置有误，请核验...")
                return False
            user_defined_blackdomain_path = instrusion_cfg.get("user_defined_blackdomain_path", "")
            if not os.path.exists(user_defined_blackdomain_path):
                flow_log.logger.debug("instrusion user_defined_blackip_path 配置有误，请核验...")
                return False
            suricata_yaml = instrusion_cfg.get("suricata_yaml", "")
            if not os.path.exists(suricata_yaml):
                flow_log.logger.debug("instrusion suricata_yaml 配置有误，请核验...")
                return False
            classtype_cfg_path = instrusion_cfg.get("classtype_cfg_path", "")
            if not os.path.exists(classtype_cfg_path):
                flow_log.logger.debug("instrusion classtype_cfg_path 配置有误，请核验...")
                return False

            task_type = instrusion_cfg.get("task_type", {})
            if "vlan" in task_type:
                if vlan not in netcard_name.get_netcard():
                    flow_log.logger.debug("instrusion 网卡配置有误，请核验...")
                    return False
            else:
                if not os.path.exists(str(pcap)):
                    flow_log.logger.debug("instrusion 离线包不存在，请核验...")
                    return False
                else:
                    filnenmae, filetype = os.path.splitext(pcap)
                    if filetype not in ['.pcap', '.pcapng']:
                        flow_log.logger.debug("instrusion 离线包格式不正确，请核验...")
            path = instrusion_cfg.get("executable")
            if not os.path.exists(path):
                flow_log.logger.debug("instrusion executable配置有误，请核验...")
                return False
            if "vlan" in task_type:
                if vlan not in netcard_name.get_netcard():
                    flow_log.logger.debug("instrusion 网卡配置有误，请核验...")
                    return False
            else:
                if not os.path.exists(str(pcap)):
                    flow_log.logger.debug("instrusion 离线包不存在，请核验...")
                    return False
                else:
                    filnenmae, filetype = os.path.splitext(pcap)
                    if filetype not in ['.pcap', '.pcapng']:
                        flow_log.logger.debug("instrusion 离线包格式不正确，请核验...")
                        return False

            flow_log.logger.debug("instrusion 配置通过")
            return True
        except Exception, e:
            msg = traceback.format_exc()
            flow_log.logger.error(msg)
            return False

    def suricata_vlan(self, command):
        try:
            os.system(command)
        except Exception, e:
            msg = traceback.format_exc()
            flow_log.logger.error(msg)

    def run(self):
        try:
            vlan = self.cfg.get("vlan")
            pcap = self.cfg.get("pcap")
            type = self.cfg.get("task_type")
            if self.cfg_check():
                self.path = self.cfg.get("path")
                suricata_yaml = self.cfg.get("instrusion_cfg").get("suricata_yaml")
                executable = self.cfg.get("instrusion_cfg").get("executable")
                if "vlan" in type:
                    mode = ' -i ' + vlan
                else:
                    mode = ' -r ' + pcap
                try:
                    blackip_obj = blacks.Blackip(cfg=self.cfg.get("instrusion_cfg", {}).get("mongo_db", {}),
                                                 blackip_path=self.cfg.get("instrusion_cfg", {}).get(
                                                     "user_defined_blackip_path", ""))
                    blackdomain_obj = blacks.Blackdomain(cfg=self.cfg.get("instrusion_cfg", {}).get("mongo_db", {}),
                                                         blackdomain_path=self.cfg.get("instrusion_cfg", {}).get(
                                                             "user_defined_blackdomain_path", ""))
                except Exception, e:
                    msg = traceback.format_exc()
                    flow_log.logger.error(msg)
                if not blackip_obj.blackip_write():
                    flow_log.logger.debug("黑ip写入失败")
                if not blackdomain_obj.blackdomain_write():
                    flow_log.logger.debug("黑链接写入失败")
                command = executable + " -c " + suricata_yaml + mode
                flow_log.logger.debug(command)
                w = threading.Thread(target=self.suricata_vlan, args=[command])
                w.start()  # 创建任务线程，在ready状态下启动
                x = threading.Thread(target=self.redis_data, args=[self.cfg])
                x.start()
        except Exception, e:
            msg = traceback.format_exc()
            flow_log.logger.error(msg)

    def stop(self):
        try:
            flow_log.logger.debug("正在停止安全事件检测")
            pool = redis.ConnectionPool(host='127.0.0.1', port=6379)
            r = redis.Redis(connection_pool=pool)
            r.flushdb()
            os.system("ps -ef|grep " + self.cfg.get("path") + " |grep -v grep|awk '{print $2}'|xargs kill -9")
            self.task["status"] = 2
            return True
        except Exception, e:
            msg = traceback.format_exc()
            flow_log.logger.error(msg)
            return False

    def area_info(self, ip, geo_db):
        if ipdivide.is_internal_ip(ip):
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
                    response = reader.city(ip)
                    country = response.country.names.get('zh-CN', u'')
                    province = response.subdivisions.most_specific.names.get('zh-CN', u'')
                    city = response.city.names.get('zh-CN', u'')
                    latitude = response.location.latitude
                    longitude = response.location.longitude
                    country_code = response.country.iso_code
                except:
                    msg = traceback.format_exc()
                    flow_log.logger.error(msg)
                if not country:
                    try:
                        response = reader.city(ip)
                        country = response.country.names.get('en', '')
                        province = response.subdivisions.most_specific.names.get('en', '')
                        city = response.city.names.get('en', '')
                        latitude = response.location.latitude
                        longitude = response.location.longitude
                        country_code = response.country.iso_code
                    except:
                        msg = traceback.format_exc()
                        flow_log.logger.error(msg)
            except:
                msg = traceback.format_exc()
                flow_log.logger.error(msg)
        ip_geo = {
            "intranet": intranet,
            "province": province,
            "city": city,
            "country": country,
            "longitude": longitude,
            "country_code": str(country_code).lower(),
            "latitude": latitude
        }
        return ip_geo

# cfg={
#     "vlan":"", #可设置网卡ens192，离线pcap包路径
#     "pcap_packet":"sqlinject.pcapng",#"/suricata/oisf/packet3.pcapng",
#     "path" : "suricata",#ndpi程序路径
#     # "access_time" :"20",#分析时长
#     # "temp_flow":"temp_flow.json",#临时分析文件
# }
#
#
# su = Suricata_es(cfg)
# su.run()
