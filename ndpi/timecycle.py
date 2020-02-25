#ecoding:utf-8
import datetime
import time

def str_time_to_utc(strtime):
    timestamp = datetime.datetime.strptime(strtime, '%Y-%m-%d %H:%M:%S')
    utc_timestamp = timestamp - datetime.timedelta(hours=1)
    return utc_timestamp.strftime('%Y-%m-%dT%H:%M:%S+0800')

def str_time_to_Mtime(strtime):
    timestamp = datetime.datetime.strptime(strtime, '%Y-%m-%d %H:%M:%S')
    return  timestamp
    # return timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')

def str_time_to_day(strtime):
    timestamp = datetime.datetime.strptime(strtime, '%Y-%m-%d %H:%M:%S')
    return timestamp.strftime('%Y-%m-%d')
# time = "2018-5-9 12:45:52"
# print str_time_to_Mtime(time)

def utc_now(utctime):
    # text = '2016-7-10T23:59:59+0800'
    timestamp = datetime.datetime.strptime(utctime, '%Y-%m-%dT%H:%M:%S+0800')
    utc_timestamp = timestamp - datetime.timedelta(hours=0)
    return (utc_timestamp.strftime('%Y-%m-%d %H:%M:%S'))


def getTimeDiff(timeStra, timeStrb):
    if timeStra <= timeStrb:
        return 0
    ta = time.strptime(timeStra, "%Y-%m-%d %H:%M:%S")
    tb = time.strptime(timeStrb, "%Y-%m-%d %H:%M:%S")
    y, m, d, H, M, S = ta[0:6]
    dataTimea = datetime.datetime(y, m, d, H, M, S)
    y, m, d, H, M, S = tb[0:6]
    dataTimeb = datetime.datetime(y, m, d, H, M, S)
    secondsDiff = (dataTimea - dataTimeb).seconds
    days = (dataTimea - dataTimeb).days
    minutesDiff = round(secondsDiff / 60, 1)
    h, m = divmod(minutesDiff, 60)
    return  ("%02d天%02d小时%02d分钟前" % (days ,h, m))

print time.localtime(time.time())