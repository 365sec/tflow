 #coding:utf8
'''
author:liulinghong
brief:elasticsearch
description:Packages elasticsearch methods for creating indexes, queries, inserts, and updates
time:2019:9:27
'''
import os
import json
import time
from os import walk
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

class ElasticObj:
    def __init__(self, index_name,index_type,ip ="172.16.39.15"):
        '''

        :param index_name: 索引名称
        :param index_type: 索引类型
        '''
        self.index_name =index_name
        self.index_type = index_type
        # 无用户名密码状态
        self.es = Elasticsearch([ip])
        #用户名密码状态
        #self.es = Elasticsearch([ip],http_auth=('elastic', 'password'),port=9200)

    def create_index(self,index_name="ott",index_type="ott_type"):
        '''
        创建索引,创建索引名称为ott，类型为ott_type的索引
        :param ex: Elasticsearch对象
        :return:
        '''
        #创建映射
        _index_mappings = {
            "mappings": {
                self.index_type: {
                    "properties": {
                        "datetime": {
                            "type": "date"
                        },
                        "payload": {
                            "type": "text"
                        },
                        "payload_printable":{
                            "type": "text"
                        },
                        "packet":{
                            "type":"text"
                        }

                    }
                }

            }
        }
        if self.es.indices.exists(index=self.index_name) is not True:
            res = self.es.indices.create(index=self.index_name, body=_index_mappings)
            print res

    def Index_Data(self,item):
        '''
        数据存储到es
        :return:
        '''
        res = self.es.index(index=self.index_name, doc_type=self.index_type, body=item)
        #print(res['created'])

    def bulk_Index_Data(self,ACTIONS):
        success,_  = bulk(self.es, ACTIONS, index=self.index_name)
        # print('Performed %d actions' % success)

    def Delete_Index_Data(self,id):
        '''
        删除索引中的一条
        :param id:
        :return:
        '''
        res = self.es.delete(index=self.index_name, doc_type=self.index_type, id=id)
        print res

    def Get_Data_Id(self,id):

        res = self.es.get(index=self.index_name, doc_type=self.index_type,id=id)
        print(res['_source'])
        #
        # # 输出查询到的结果
        for hit in res['hits']['hits']:
            # print hit['_source']
            print hit['_source']['last_seen'],hit['_source']['proto'],hit['_source']['link'],hit['_source']['keyword'],hit['_source']['title']

    def Get_Data_By_Body(self):
        # doc = {'query': {'match_all': {}}}
        doc = {
            "query": {
                "match_all":{}
            },
            "sort": [
                {
                    "datetime": {
                        "order": "desc"
                    }
                }
            ]
        }
        _searched = self.es.search(index=self.index_name, doc_type=self.index_type, body=doc)
        search= self.es.search(index=self.index_name, doc_type=self.index_type)

        for hit in search['hits']['hits']:
            print hit['_source']

            print hit['_source']['datetime']
        print len(search['hits']['hits'])





obj = ElasticObj("suricata_flow", "suricata_flow_type","172.16.39.15")
obj.create_index()
#obj.Index_Data()

# obj.IndexData()
#obj.Delete_Index_Data("AW1rW62rivY3Jk6-XlF2")
# csvfile = 'D:/work/ElasticSearch/exportExcels/2017-08-31_info.csv'
# obj.Index_Data_FromCSV(csvfile)
#obj.Get_Data_By_Body()
