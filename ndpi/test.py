#ecoding:utf-8
import ndpi

cfg={
    "vlan":"ens160", #可设置网卡ens192，离线pcap包路径
    "pacp":"",
    "path" : "/home/python_ndpi/ndpi/ndpiReader",#ndpi程序路径
    "access_time" :"20",#分析时长
    "temp_flow":"temp_flow.json",#临时分析文件
}

pa= ndpi.Passiveasset()
pa.run(cfg) #开启任务
#pa.stop() #结束服务
#pa.status()#返回任务状态
'''
self.Ready = 0 准备状态
self.Running = 1 运行状态
self.Termination = 2 结束状态
self.Error_state=3 异常状态
self.work_status = 0
'''
