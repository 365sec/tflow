#ecoding:utf-8
import re
import mongoclass
import os
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
class blackip():
    def __init__(self,cfg, blackip_path):
        self.path = cfg.get("path", "")
        self.port = int(cfg.get("port", 0))
        self.index = cfg.get("index", "")
        self.database = cfg.get("database", "")
        self.blackip_path =blackip_path


    def blackip_write(self):
        try:
            status,results= self.blackip_deal()
            if not status or len(results)<0:
                return False
            if not self.blackip_rule_path():
                return False
            wfile = open(self.blackip_path,"w+" )
            for data in results:
                #print data
                wfile.write(data)
            return True
        except Exception,e:
            print e
            return False




    def blackip_deal(self):
        '''
        data_format:171.7.80.88,4,90
        :return:
        '''
        try:
            blackips= self.blackip_get()
            if len(blackips)<1:
                return False,[]
            results = []
            for blackip in blackips:
                data = blackip+',4,90\n'
                results.append(data)
            return True,results
        except Exception,e:
            return False,[]



    def blackip_get(self):
        try:
            mongo_client = mongoclass.Mongoclass(self.path, self.port, self.database)
            if not self.blackip_path_check():
                return False
            total_data = mongo_client.find(self.index+"blackip", {})
            blackips=[]
            for data in total_data:
                blackip = data.get("ipaddr","")
                if blackip and self.ipcheck(blackip):
                    blackips.append(blackip)
            return  blackips
        except Exception,e:
            return []


    def blackip_path_check(self):
        try:
            if not self.path or self.port == 0 or not self.index or not self.database:
                return False
            mongo_client = mongoclass.Mongoclass(self.path, self.port,self.database)
            if not mongo_client.get_state():
                return False
            return True
        except Exception,e:
            print e
            return False

    def blackip_rule_path(self):
        try:
            if not os.path.exists(self.blackip_path):
                file = open(self.blackip_path,"w+")
                file.write("")
                return True
            else:
                return True
        except Exception,e:
            return False

    def ipcheck(self, ip_addrr):
        try:
            if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                        ip_addrr):
                return True
            else:
                return False
        except:
            return False



class blackdomain():
    def __init__(self,cfg, blackdomain_path):
        self.path = cfg.get("path", "")
        self.port = int(cfg.get("port", 0))
        self.index = cfg.get("index", "")
        self.database = cfg.get("database", "")
        self.blackdomain_path =blackdomain_path


    def blackdomain_rule_path(self):
        try:
            if not os.path.exists(self.blackdomain_path):
                file = open(self.blackdomain_path,"w+")
                file.write("")
                return True
            else:
                return True
        except Exception,e:
            return False


    def blackdomain_get(self):
        try:
            mongo_client = mongoclass.Mongoclass(self.path, self.port, self.database)
            if not self.blackdomain_path_check():
                return False
            total_data = mongo_client.find(self.index+"blackdomain", {})
            domains=[]
            for data in total_data:
                rew={}
                domain = data.get("domain","")
                classtype = data.get("reason","")
                if blackdomain and classtype:
                    rew["domain"]=domain
                    rew["classtype"] = classtype
                    domains.append(rew)
            return  domains
        except Exception,e:
            return []


    def blackdomain_path_check(self):
        try:
            if not self.path or self.port == 0 or not self.index or not self.database:
                return False
            mongo_client = mongoclass.Mongoclass(self.path, self.port,self.database)
            if not mongo_client.get_state():
                return False
            return True
        except Exception,e:
            print e
            return False


    def blackdomain_deal(self):
        '''
        data_format:171.7.80.88,4,90
        :return:
        '''
        try:
            blackdomain= self.blackdomain_get()
            if len(blackdomain)<1:
                return False,[]
            results = []
            sidindex=7700000
            for rew in blackdomain:
                sidindex+=1
                data = '''alert dns any any -> any any (msg:"黑域名"; dns_query; content:"'''+rew.get("domain")+'''"; nocase;endswith; classtype:'''+rew.get("classtype")+'''; metadata: former_category; sid:'''+str(sidindex)+'''; rev:1;metadata:created_at 2018_09_19; )\n'''
                results.append(data)
            return True,results
        except Exception,e:
            return False,[]


    def blackdomain_write(self):
        try:
            status,results= self.blackdomain_deal()
            if not status or len(results)<0:
                return False
            if not self.blackdomain_rule_path():
                return False
            wfile = open(self.blackdomain_path,"w+" )
            for data in results:
                #print data
                wfile.write(data)
            return True
        except Exception,e:
            print e
            return False