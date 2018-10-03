import multiprocessing
import logging
from scapy.all import * as scapy

DEBUG = 1
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

def debug(debug_string):
    if DEBUG:
        print(debug_string)
        
def ip_range(start, end):
    start = ipaddress.IPv4Address(start)
    end = ipaddress.IPv4Address(end)
    ip_list = [start]
    temp = start
    while temp != end:
        temp += 1
        ip_list.append(temp)
    # debug('list: {}'.format(ip_list))
    return ip_list

def TCP_stealth_scan(ip_addr, port, results):

def scan(ip_range, delay):

def print_results(results):
    for port, result in results.items():
        if result == 'Open':
            print('{0}: {1}'.format(port, result))

if __name__ == '__main__':
    ip_list = ip_range('192.168.1.0', '192.168.1.255')
    scan(ip_list, 1)
