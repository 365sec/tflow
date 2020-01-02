#coding:utf8
from flask_restplus import Namespace, Resource
from flask import request
import os
import sys
from flow_assets.scheduler import get_scheduler
import logging
import json
import paramiko
task_namespace = Namespace("task", description="Endpoint to retrieve task")
logger = logging.getLogger('tapp_flow')
@task_namespace.route('/start')
class Create(Resource):
    def get(self):
        sc = get_scheduler()
        logger.info("create")
        logger.info(id(sc))
        return {"get": "hello world"}
    def post(self):
        try:
            sc = get_scheduler()
            logging.info("post create")
            cfg = json.loads(request.data)
            # cfg={
            #     "vlan": "sqlinject.pcapng",  # 可设置网卡ens192，离线pcap包路径
            #       "pacp": "/pacp_path",
            #     "path": "./ndpiReader",  # ndpi程序路径
            #     "access_time": "20",  # 分析时长
            #     "temp_flow": "temp_flow.json",  # 临时文件
            #     "task_type" : "passive"
            # }
#            if  cfg.get("es_passive_name",None) == None:
#                return {"success": False, "msg": "es索引名 不能为空"}
#            if  cfg.get("es_passive_type",None) == None:
#                return {"success": False, "msg": "es索引类型 不能为空"
#            if  cfg.get("path",None) == None:
#                return {"success": False, "msg": "es IP地址 不能为空"}
            if cfg.get("vlan",None) == None:
                logger.debug("vlan 不能为空")
                return {"success": False, "msg": "vlan 不能为空"}
            if cfg.get("path", None) == None:
                logger.debug("path 不能为空")
                return {"success": False, "msg": "path 不能为空"}
            task_type = cfg.get("task_type", None)
            if task_type  == None:
                logger.debug("任务类型 错误")
                return {"success": False, "msg": "任务类型  不能为空"}
            else:
                if task_type not in ["passive_vlan", "suricata_vlan","passive_pcap", "suricata_pcap"]:
                    logger.debug("任务类型  不能为空")
                    return {"success": False, "msg": "任务类型 错误"}
                if  task_type == "passive_pcap" or task_type =="suricata_pcap":
                    if cfg.get("path", "") == "":
                        logger.debug("pcap路径不能为空")
                        return {"success": False, "msg": "pcap路径不能为空 "}
                if  task_type == "passive_vlan" or task_type =="suricata_vlan":
                    if cfg.get("vlan", "") == "":
                        logger.debug("pcap路径不能为空")
                        return {"success": False, "msg": "vlan路径不能为空"}
            type = cfg.get("task_type")
            for task in sc.tasklist:
                task_cfg = task.get("cfg")
                task_typex = task_cfg.get("task_type")
                status = task.get("status")
                if "suricata" in type and "suricata" in task_typex and status in [0,1]:
                    logger.debug("重复下发任务")
                    return {"success": False, "msg": "重复下发任务"}
                if "passive" in type and "passive" in task_typex and status in [0,1]:
                    logger.debug("重复下发任务")
                    return {"success": False, "msg": "重复下发任务"}
                # if "passive" in type and "suricata" in task_typex and status in [0,1]:
                #     logger.debug("已存在入侵检测任务")
                #     return {"success": False, "msg": "已存在入侵检测任务"}
                # if "suricata" in type and "passive" in task_typex and status in [0,1]:
                #     logger.debug("已存在流量分析任务")
                #     return {"success": False, "msg": "已存在流量分析任务"}
            taskid = sc.createtask(cfg)
            logger.debug("成功下发任务")
            return   {"success": True,"taskid":taskid, "msg": "成功下发任务"}
        except Exception as e:
            print  {"success": False,"msg": str(e)}
            logging.error(str(e))
        return {"success": False,"msg":""}




# @task_namespace.route('/create')
# class Create(Resource):
#     def get(self):
#         sc = get_scheduler()
#         logging.info("create")
#         logging.info(id(sc))
#         return {"get": "hello world"}
#
#     def post(self):
#         try:
#             sc = get_scheduler()
#             logging.info("post create")
#             cfg = json.loads(request.data)
#             if cfg.get("host",None) == None:
#                 return {"success": False, "msg": "host 不能为空"}
#             if cfg.get("port", None) == None:
#                 return {"success": False, "msg": "port 不能为空"}
#             if cfg.get("username", None) == None:
#                 return {"success": False, "msg": "username 不能为空"}
#             if cfg.get("pwd", None) == None:
#                 return {"success": False, "msg": "pwd 不能为空"}
#             scanType = cfg.get("scanType", None)
#             if scanType  == None:
#                 return {"success": False, "msg": "扫描类型 不能为空"}
#             else:
#                 if scanType not in ["all", "fast", "user"]:
#                     return {"success": False, "msg": "扫描类型 错误 "}
#                 if  scanType == "user":
#                     if    cfg.get("path", "") == "":
#                         return {"success": False, "msg": "自定义模式扫描路径不能为空 "}
#
#             taskid = sc.createtask(cfg)
#             return   {"success": True,"taskid":taskid, "msg": ""}
#         except Exception as e:
#             print  {"success": False,"msg": str(e)}
#
#         return {"success": False,"msg":""}


@task_namespace.route('/status')
class Status(Resource):
    def get(self):
        sc = get_scheduler()
        logging.info("create")
        logging.info(id(sc))
        return {"get": "hello world"}

    def post(self):
        try:
            sc = get_scheduler()
            cfg = json.loads(request.data)
            logging.info("post create")
            taskid = cfg.get("taskid",None)
            if not taskid :
                # print '===='
                for task in sc.tasklist:
                    if 'suricata' in task.get("cfg").get("task_type") and 'suricata' in cfg.get("task_type") and task.get("status") in [0,1]:
                        taskid = task.get("taskid")
                        break
                    if 'passive' in task.get("cfg").get("task_type") and 'passive' in cfg.get("task_type") and task.get("status") in [0,1]:
                        taskid = task.get("taskid")
                        break
            # print taskid
            if taskid != None:
                taskinfo = sc.taskinfo(taskid)
                if taskinfo != None:
                    return {"success": taskinfo.get("success",True), "msg": taskinfo.get("msg",""), "taskinfo": taskinfo}
                else:
                    return {"success": False, "msg": "任务不存在"}
        except Exception as e:
            s = sys.exc_info()
            print "Error '%s' happened on line %d" % (s[1], s[2].tb_lineno)
            return   {"success": False, "msg": str(e)}
        return {"success": False,"msg":""}



# @task_namespace.route('/delete')
# class Delete(Resource):
#     def get(self):
#         sc = get_scheduler()
#         logging.info("create")
#         logging.info(id(sc))
#         return {"get": "hello world"}
#
#     def post(self):
#         try:
#             sc = get_scheduler()
#             logging.info("post create")
#             cfg = json.loads(request.data)
#             taskid = cfg.get("taskid", None)
#             if taskid != None :
#                 if sc.deltask(taskid) == True:
#                     return {"success": True, "msg": ""}
#                 else:
#                    return {"success": False, "msg": "任务不存在"}
#             else:
#                 return {"success": False, "msg": "taskid 不能为空"}
#         except Exception as e:
#             return {"success": False, "msg": str(e)}


@task_namespace.route('/delete')
class Delete(Resource):
    def get(self):
        sc = get_scheduler()
        logging.info("create")
        logging.info(id(sc))
        return {"get": "hello world"}
    def post(self):
        try:
            sc = get_scheduler()
            logging.info("post create")
            cfg = json.loads(request.data)
            print cfg
            taskid = cfg.get("taskid", None)
            task_type = cfg.get("task_type", None)
            print task_type
            print taskid,'----->'
            if not taskid :
                print '===='
                for task in sc.tasklist:
                    print task.get("status")
                    if 'suricata' in task.get("cfg").get("task_type") and 'suricata' in cfg.get("task_type") and task.get("status") in [0,1]:
                        taskid = task.get("taskid")
                        print '********',taskid
                        break
                    if 'passive' in task.get("cfg").get("task_type") and 'passive' in cfg.get("task_type") and task.get("status") in [0,1]:
                        taskid = task.get("taskid")
                        break
            if taskid != None :
                if sc.deltask(taskid) == True:
                    return {"success": True, "msg": "任务关闭成功"}
                else:
                   return {"success": False, "msg": "任务不存在"}
            else:
                return {"success": False, "msg": "taskid 不能为空"}
        except Exception as e:
            return {"success": False, "msg": str(e)}