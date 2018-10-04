import time
import multiprocessing
import logging
from netaddr import IPNetwork
from scapy.all import *

DEBUG = 1
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

def debug(debug_string):
    if DEBUG:
        print(debug_string)

def ip_range(ip_range):
    ip_list = []
    for ip_addr in IPNetwork(ip_range):
        ip_list.append(str(ip_addr))
    return ip_list
        
def TCP_stealth_scan(ip_addr, port, results):
    closed = 0
    source_port = RandShort()
    packet = IP(dst=ip_addr)/TCP(sport=source_port, dport=port, flags='S')
    response = sr1(packet, timeout=2)
    if str(type(response)) == "<type 'NoneType'>":
        closed += 1
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            send_reset = sr(IP(dst=ip_addr)/TCP(sport=source_port, dport=port, flags='AR'), timeout=1)
            print('{} Open'.format(port))
        elif response.getlayer(TCP).flags == 0x14:
            closed += 1
    return closed

def ping(ip_addr, active_ips):
    print('{}'.format(ip_addr))
    packet = IP(dst=ip_addr)/ICMP()
    response = sr1(packet, timeout=10)
    if response == None:
        return
    elif response.haslayer(ICMP):
        active_ips.append(ip_addr) 

def print_results(results):
    for port, result in results.items():
        if result == 'Open':
            print('{0}: {1}'.format(port, result))

if __name__ == '__main__':
    active_ips = []
    conf.verb = 0
    start_time = time.time()
    ports = range(1, 1024)
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count()*10)
    ip_list = ip_range('192.168.207.0/24')
    results = [pool.apply_async(ping, (ip_addr, active_ips, )) for ip_addr in ip_list]
    print('{}'.format(active_ips))
#    for ip_addr in ip_list:
#        if ping(ip_addr):
#            print('{} is up, starting scan'.format(ip_addr))
#            results = [pool.apply_async(TCP_stealth_scan, (port, )) for port in ports]
#            for result in filter(lambda i : i.get() != None, results):
#                closed += result.get()[0]
#            duration = time.time() - start_time
#            print('{0} scan completed in {1}'.format(ip_addr, duration))
#            print('{0} closed ports in {1} total ports scanned'.format(closed, len(ports)))
#        else:
#            print('{} is Down'.format(ip_addr))
#
