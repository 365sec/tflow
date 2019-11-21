#coding:utf-8
import Queue
import threading
import time
import uuid
import copy
from  scanner import  Scanner
from ndpi import ndpi
from ids import redis_es
import logging

class Scheduler(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        print "Scheduler  init"
        self.tasklist=[]



    def createtask(self,cfg):
        taskid = str(uuid.uuid4())
        task={"taskid":taskid,"cfg":cfg,"status":0}
        self.tasklist.append(task)
        logging.info('createtask running ' + str(task))
        return taskid

    def taskinfo(self,taskid):
        t = None
        for task in  self.tasklist :
            if task["taskid"] == taskid:
                t = copy.deepcopy(task)
        return t


    def deltask(self,taskid):
        index = -1
        for  i in  range(len(self.tasklist)):
            if self.tasklist[i].get("taskid","") == taskid:
                index = i
        print index
        if index != -1 :
            print 'delete__________'
            print self.tasklist[index]
            if 'passive' in self.tasklist[index].get('cfg').get("task_type"):
                pa = ndpi.Passiveasset(self.tasklist[index])
                pa.stop()
            elif  'suricata' in self.tasklist[index].get('cfg').get("task_type"):
                su = redis_es.Suricata_es(self.tasklist[index])
                su.stop()
            del self.tasklist[index]
            return True

        print False

    # vcan_cfg = """{
    #     "vlan": "ens160",
    #     "pacp": "/home/python_ndpi/ndpi/sqlinject.pcapng",
    #     "path": "/home/python_ndpi/ndpi/ndpiReader",
    #     "access_time": "20",
    #     "temp_flow": "temp_flow.json",
    #     "task_type" : "passive_vlan"
    # }
    # """

    def run(self):
        while True:
            for task in self.tasklist:
                if task["status"] == 0:
                    task["status"] = 1
                    cfg =task.get("cfg")
                    if 'passive' in cfg.get("task_type"):
                        pa = ndpi.Passiveasset(task)
                        pa.run()
                    elif 'suricata' in cfg.get("task_type"):
                        su = redis_es.Suricata_es(task)
                        su.run()
                    logging.info('task running ' + str(task))
            time.sleep(6)


scheduler=Scheduler()
logging.info(id(scheduler))
print scheduler

def get_scheduler():
    logging.info(id(scheduler))
    return scheduler

def init_scheduler():
    logging.info("init_scheduler  start ...")
    scheduler.start()
    logging.info(id(scheduler))
    print id(scheduler)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    logger.info('This is a log info')
    sc = Scheduler()
    thr = sc.start()
    cfg = {"host": "172.16.39.15", "port": 22, "username": "root", "pwd": "www.365sec.com", "folder": ""}
    sc.createtask(cfg)
    sc.join()


    print "ccc"