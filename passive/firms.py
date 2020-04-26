# ecoding:utf-8
import sys


class BTree:  # B树
    def __init__(self, layer=0, data=()):
        self.maping = {}
        self.layer = layer
        self.data = data


def read_file(path):
    datalist = open(path).readlines()
    return datalist


def mac2key(mac):
    try:
        mac = mac.replace(" ", "").replace(":", "").strip()
        if len(mac) > len("000002"):
            index = mac.find("/")
            if index == -1:
                return int(mac, 16)
            length = int(mac[index + 1:])
            if length % 4:
                return None
            mac = mac[0:length / 4]
        else:
            mac = mac[0:6]
        return int(mac, 16)
    except:
        return None


def data_in_BTree(datalist, redict):
    for data in datalist:
        if len(data) > 5:
            temp_list = str(data[0:-1]).split(" ", 3)
            rows = list(filter(None, temp_list))
            if len(rows) < 3:
                rows.extend(["", "", ""])
            if len(rows[0]) < len("00:00:02") and ":" not in rows[0]:
                continue
            try:
                tkey = mac2key(rows[0])
                if tkey:
                    product, firms = rows[1], rows[2][0:-1]
                    treedata = product
                    redict[tkey] = treedata
            except Exception, e:
                print e
                pass


def insert(datalist=[]):
    present = BTree(layer=0)
    try:
        for data in datalist:
            tkey = data[0].split(":")
            son = present.maping.get(tkey[0], "")
            if son:
                grandson = son.maping.get(tkey[1], "")
                if grandson:
                    grandsonson = grandson.maping.get(tkey[2], "")
                    if grandsonson:
                        grandsonson.data = data[1]
                    else:
                        grandsonson = BTree(data=data[1], layer=3)
                    grandson.maping[tkey[2]] = grandsonson
                else:
                    grandsonson = BTree(data=data[1], layer=3)
                    grandson = BTree(layer=2)
                    grandson.maping[tkey[2]] = grandsonson
                son.maping[tkey[1]] = grandson
            else:
                grandsonson = BTree(data=data[1], layer=3)
                grandson = BTree(layer=2)
                grandson.maping[tkey[2]] = grandsonson
                son = BTree(layer=1)
                son.maping[tkey[1]] = grandson
            present.maping[tkey[0]] = son
    except Exception, e:
        print e
    return present


def result(present, tkey=""):
    keys = tkey.strip().split(":")
    if len(keys) != 3:
        return False
    try:
        return present.maping.get(keys[0]).maping.get(keys[1]).maping.get(keys[2]).data
    except Exception, e:
        return False


def firms(mac_address):
    mac = mac_address[0:8]
    datalist = read_file("etharUIL.txt")
    relist = []
    data_in_BTree(datalist, relist)
    Root = insert(datalist=relist)
    # data_in_BTree(datalist)
    return result(Root, mac)


def search_inlist(mac, firm_lib):
    try:
        redict = {}
        datalist = read_file(firm_lib)
        data_in_BTree(datalist, redict)
        maclist = {}
        maclist[1] = mac[0:13]
        maclist[2] = mac[0:11]
        maclist[3] = mac[0:8]
        tkey = mac2key(maclist[1])
        if redict.get(tkey, ""):
            return redict.get(tkey, "")
        tkey = mac2key(maclist[2])
        if redict.get(tkey, ""):
            return redict.get(tkey, "")
        tkey = mac2key(maclist[3])
        if redict.get(tkey, ""):
            return redict.get(tkey, "")
        return None
    except Exception, e:
        s = sys.exc_info()
        print "Error '%s' happened on line %d" % (s[1], s[2].tb_lineno)
        return None
