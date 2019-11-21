import json

import IPy as IPy

cfg = {
   "instrusion":{
        "geo_db" : "/home/td01/GeoLite2-City.mmdb",
        "executable":"./suricata",
        "NIC1": "ens160",
        "NIC2": "ens192",
        "default_time": 60*60*24,
        "suricata_yaml":"/home/flow/service_test/suricata.yaml",
        "mongo_db": {
			"path": "172.16.39.15",
			"port": "27017",
            "database" :"flow_analysis",
			"index": "instrusion"
		},
        "es_instrusion": {
            "path": "0.0.0.0",
            "username": "",
            "password": "",
            "port": 9200,
            "index_name": "suricata_instrusion",
            "index_type": "suricata_instrusion_type",
        },
        "es_flow":{
            "path":"0.0.0.0",
            "username":"",
            "password":"",
            "port":9200,
            "index_name": "suricata_flow",
            "index_type": "suricata_flow_type",
        },
        "redis":{
                "redis_path":"127.0.0.1",
                "redis_port":6379
         }

    },
   "passive":{
        "geo_db" : "/home/td01/GeoLite2-City.mmdb",
        "executable":"./ndpiReader",
        "temp_flow":"temp_flow.json",
        "NIC1": "ens160",
        "NIC2": "ens192",
        "default_access_time": 60*60*24,
        "es_passive":{
            "path":"0.0.0.0",
            "username":"",
            "password":"",
            "port":9200,
            "index_name":"passive_flow",
            "index_type":"passive_flow_type",
                },
        "passive_hz":5,
        "mongo_db":{
            "path":"172.16.39.15",
            "port" :"27017",
            "database" :"flow_analysis",
            "index":"passive_flow",
       }
    },
    "common":{
        "domain":"http://0.0.0.0:5050/",
    }
}

file =open("cfg.json","w+")
file.write(json.dumps(cfg))


print '192.168.2.100' in IPy.IP('192.168.1.0/24')