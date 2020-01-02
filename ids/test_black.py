#ecoding:utf-8
import blacks

cfg={
    "path": "172.16.39.15",
    "index": "instrusion",
    "port": "27017",
    "database": "flow_analysis"
}
path = "test.rules"


if __name__=="__main__":
    # blackip_obj = blacks.blackip(cfg=cfg,blackip_path=path)
    # blackip_obj.blackip_write()

    blackdomain_obj = blacks.blackdomain(cfg=cfg,blackdomain_path=path)
    blackdomain_obj.blackdomain_write()

