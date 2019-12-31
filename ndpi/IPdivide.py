#ecoding:utf-8
import re
import IPy

def ip_into_int(ip):
    # (((((192 * 256) + 168) * 256) + 1) * 256) + 13
    return reduce(lambda x, y: (x << 8) + y, map(int, ip.split('.')))
def is_internal_ip(ip):
    try:
        ip = ip_into_int(ip)
        net_a = ip_into_int('10.255.255.255') >> 24
        net_b = ip_into_int('172.31.255.255') >> 20
        net_c = ip_into_int('192.168.255.255') >> 16
        return ip >> 24 == net_a or ip >> 20 == net_b or ip >> 16 == net_c
    except Exception,e:
        return True


def ipcheck(ip_addrr):
    '''
    :param ip_addrr:
    :return:
    '''
    try:
        if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                    ip_addrr):
            return True
        else:
            return False
    except:
        return False


def ip_graph_check(ip,ip_graph):
    return ip in IPy.IP(ip_graph)
# if __name__ == '__main__':
#     ip = '172.16.39.222'
#     print ip, is_internal_ip(ip)
#     ip = '10.2.0.1'
#     print ip, is_internal_ip(ip)
#     ip = '172.15.1.1'
#     print ip, is_internal_ip(ip)