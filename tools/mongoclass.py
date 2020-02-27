#ecoding:utf-8
from pymongo import MongoClient

class Mongoclass(object):
    '''
    some mongo tools
    '''
    def __init__(self, address, port, database):
        self.conn = MongoClient(host=address, port=port)
        self.db = self.conn[database]

    def get_state(self):
        '''
        连接状态
        :return: False or True
        '''
        return self.conn is not None and self.db is not None

    def insert_one(self, collection, data):
        '''
        插入一条记录
        :param collection: mongo collection name
        :param data: data which will be inserted,dict
        :return: after insertting data'id
        '''
        if self.get_state():
            ret = self.db[collection].insert_one(data)
            return ret.inserted_id
        else:
            return None

    def insert_many(self, collection, data):
        '''
        一次插入多条数据
        :param collection:mongo collection name
        :param data: data which will be inserted,list[dicts]
        :return: True or False
        '''
        if self.get_state():
            ret = self.db[collection].insert_many(data)
            return True
        else:
            return False

    def update(self, collection, data):
        '''
        更新多条记录
        :param collection:mongo collection name
        :param data: data format:{key:[old_data,new_data]}
        :return:
        '''
        data_filter = {}
        data_revised = {}
        for key in data.keys():
            data_filter[key] = data[key][0]
            data_revised[key] = data[key][1]
        if self.get_state():
            return self.db[collection].update_one(data_filter, {"$set": data_revised}).modified_count
        return 0

    def update_one(self, collection, data):
        '''
        更新一条数据
        :param collection:
        :param data:
        :return:
        '''
        # data format:
        # {key:[old_data,new_data]}
        fileter = data[0]
        replace = data[1]
        if self.get_state():
            return self.db[collection].update_one(fileter, {"$set": replace})
        return 0


    def find(self, col, condition, column=None):
        '''
        数据查找
        :param col:
        :param condition: filter:none,return all,else return data after filter
        :param column:
        :return:
        '''
        if self.get_state():
            if column is None:
                return self.db[col].find(condition)
            else:
                return self.db[col].find(condition, column)
        else:
            return None

    def delete(self, col, condition):
        '''
        delete many
        :param col:
        :param condition:
        :return:
        '''
        if self.get_state():
            return self.db[col].delete_many(filter=condition).deleted_count
        return 0

    def mongodb_size_count(self, col, condition):
        try:
            if self.get_state():
                mongo_size=self.db[col].find(condition).count()
                if mongo_size > 10000:
                    return False
                else:
                    return True
            else:
                return False
        except:
            return False
# if __name__ == '__main__':
    # # unit test
    # import time
    # import random
    #
# db = Mongoclass("172.16.39.15", 27017, "passive_flow")
# print "deleted count: ", db.delete("passive_flow",{"test":1})
#     # print(db.get_state())
# data1= {
#     "test":1
# }
# data2={
#     "test":2
# }
# a11=[]
# a11.append(data1)
# a11.append(data2)
#     # print db.insert_one("passive_flow",data2)
# print db.find("passive_flow",{'test':1}).count()


#
# print(db.update_one("passive_flow", a11))
# for data in  db.find("passive_flow", {}):
#     print data
    # # print(db.delete("ut", {}))
    # # print(time.time())
    # # start_time = int(time.time() * 1e6)
    # # for i in range(100):
    # #     t = int(time.time() * 1e6)
    # #     db.insert_one("ut", {"username": str(t),
    # #                          "timestamp": t,
    # #                          "password": "aaaa",
    # #                          "telephone": str(random.random() * 1000000)})
    # # print("deleted count: ", db.delete("ut", {"timestamp": {"$gt": start_time + 500}}))
    # # print(db.find("ut", {}).count())
    # #
    # # print(db.find("ut", {}, {"password": 1, "username": 1}).count())
