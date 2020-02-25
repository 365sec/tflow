#ecoding:utf-8
import time
import traceback

import mongoclass

class FlowCounter():
    def __init__(self,passive_cfg):
        self.flow_all=[]
        self.wait_update=[]
        self.wait_insert=[]
        # self.flow_protocol=[]
        # self.flow_event = []
        # self.flow_vlan = []
        self.status = 0
        self.passive_cfg = passive_cfg
        status,length = self.read_flow_from_db()
        print status,"成功加载"+str(length)
        print "init successfully!"
        self.status =1
        self.sleep_time = 10 #刷库时间,秒


    def read_flow_from_db(self):
        try:
            mongo_db = self.passive_cfg.get("mongo_db")
            if not mongo_db:
                return False,0
            mongo_path = mongo_db.get("path")
            mongo_port = mongo_db.get("port")
            mongo_index = str(mongo_db.get("index")) + "flowcounter"
            mongo_database = mongo_db.get("database")
            mongo_client = mongoclass.Mongoclass(mongo_path, int(mongo_port), mongo_database)
            if not mongo_client.get_state():
                return False
            all_data = mongo_client.find(mongo_index,{})
            for data in all_data:
                try:
                    data.pop('_id')
                    self.flow_all.append(data)
                except:
                    msg = traceback.format_exc()
                    print msg
            return True,len(self.flow_all)
        except Exception,e:
            msg = traceback.format_exc()
            print msg
            return True,0

    def get_data_from_flow(self,tag,object_name,s2c,c2s,last_seen,s_to_c_pkts,c_to_s_pkts):
        try:
            if tag not in ["all","ipaddr","protocol","event","vlan","last_seen"]:
                return False
            if tag != "all":
                if not object_name:
                    return False
            # filter = {
            #     "tag": tag,
            #     "object":object,
            # }
            # bytes_ipaddr = s2c_bytes+ c2s_bytes
            # mongo_client_filter = mongo_client.find(mongo_index,filter)
            result_list=[]
            result_list = self.find_data_in_list(self.flow_all, tag, object_name)
            #print len(result_list)
            s2c_bytes = float(s2c)
            c2s_bytes = float(c2s)
            bytes = s2c_bytes + c2s_bytes
            if len(result_list)< 1:
                content = {
                    "tag": tag,
                    "object": object_name,
                    "bytes": bytes,
                    "s2c_bytes": s2c_bytes,
                    "c2s_bytes": c2s_bytes,
                    "date": last_seen,
                    "s2c_packets":s_to_c_pkts,
                    "c2s_packets": c_to_s_pkts
                }
                self.flow_all.append(content)
                self.wait_insert.append(content)
            else:
                # preor_s2c_bytes = content.get("s2c_bytes")
                # preor_c2s_bytes = content.get("s2c_bytes")
                #print tag,"------------>",s2c_bytes,c2s_bytes
                for content in result_list:
                    s2c_bytes += float(content.get("s2c_bytes"))
                    c2s_bytes += float(content.get("c2s_bytes"))
                    bytes += float(content.get("bytes"))
                #print tag, "1------------>", s2c_bytes, c2s_bytes
                after_content = {
                    "tag": tag,
                    "object": object_name,
                    "bytes": bytes,
                    "s2c_bytes": s2c_bytes,
                    "c2s_bytes": c2s_bytes,
                    "date": last_seen,
                    "s2c_packets": s_to_c_pkts,
                    "c2s_packets": c_to_s_pkts
                }
                # if len(result_list)>1:
                for content in result_list:
                    try:
                        self.flow_all.remove(content)
                    except:
                        msg = traceback.format_exc()
                        print msg
                self.flow_all.append(after_content)
                self.wait_update.append(after_content)
            # if tag == 'all':
            #     self.flow_all= operate_list
            # elif tag == "protocol":
            #     self.flow_protocol= operate_list
            # elif tag == "event":
            #     self.flow_event= operate_list
            # elif tag == "vlan":
            #     self.flow_vlan= operate_list
        except Exception,e:
            msg = traceback.format_exc()
            print msg

    def find_data_in_list(self,list,tag,object_name):
        try:
            return filter(lambda content: content.get("tag","")==tag and  content.get("object","")==object_name , list)
        except:
            msg = traceback.format_exc()
            print msg
            return []


    def save_data_in_db(self):
        while self.status:
            try:
                time.sleep(self.sleep_time)
                mongo_db = self.passive_cfg.get("mongo_db","")
                if not mongo_db:
                    print "no db"
                    continue
                mongo_path = mongo_db.get("path")
                mongo_port = mongo_db.get("port")
                mongo_index = str(mongo_db.get("index")) + "flowcounter"
                mongo_database = mongo_db.get("database")
                mongo_client = mongoclass.Mongoclass(mongo_path, int(mongo_port), mongo_database)
                if not mongo_client.get_state():
                    print "db error"
                for content in self.wait_update:
                    try:
                        tag = content.get("tag","")
                        if tag not in ["all","ipaddr","protocol","event","vlan","last_seen"]:
                            continue
                        if tag == "all":
                            condition={"tag":"all"}
                            mongo_client.update_one(mongo_index,[condition, content])
                        else:
                            object_name= content.get("object","")
                            condition = {"tag":tag,"object":object_name}
                            mongo_client.update_one(mongo_index, [condition, content])

                    except:
                        msg = traceback.format_exc()
                        print msg

                try:
                    for content in self.wait_insert:
                        tag = content.get("tag", "")
                        if tag not in ["all", "ipaddr", "protocol", "event", "vlan","last_seen"]:
                            self.wait_insert.remove(content)
                            continue
                    if len(self.wait_insert)>0:
                        mongo_client.insert_many(mongo_index,self.wait_insert)
                except Exception, e:
                    msg = traceback.format_exc()
                    print msg

                self.wait_update=[]
                self.wait_insert=[]
            except Exception, e:
                msg = traceback.format_exc()
                print msg


