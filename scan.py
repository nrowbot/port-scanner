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
        
def TCP_stealth_scan(ip_range, ports):
    closed = 0
    active = {}
    source_port = RandShort()
    packet = IP(dst=ip_range)/TCP(sport=source_port, dport=ports, flags='S')
    ans, unans = sr(packet, timeout=2)
    sr(IP(dst=ip_range)/TCP(sport=source_port, dport=ports, flags='R'), timeout=2)
    for answer in ans:
        # TODO: figure out how this works for a range of IP addresses
        print('IP: {}'.format(answer[1][1].src))
        print('Port: {0} returned flags: {1}'.format(answer[1][1].sport,answer[1][1].flags))
        if answer[1][1].flags == 'RA':
            active_ports.append(answer[1][1].sport)
    
#    if str(type(ans)) == "<type 'NoneType'>":
#        closed += 1
#    elif response.haslayer(TCP):
#        if response.getlayer(TCP).flags == 0x12:
#            send_reset = sr(IP(dst=ip_addr)/TCP(sport=source_port, dport=port, flags='AR'), timeout=1)
#            print('{} Open'.format(port))
#        elif response.getlayer(TCP).flags == 0x14:
#            closed += 1

def ping(ip_range):
    active_ips = []
    packet = IP(dst=ip_range)/ICMP()
    ans, unans = sr(packet, timeout=2)
    for answer in ans:
        active_ips.append(answer[1].src)
    return active_ips

def print_results(results):
    for port, result in results.items():
        if result == 'Open':
            print('{0}: {1}'.format(port, result))

def test(result):
    print(result)
    print('done')

if __name__ == '__main__':
    conf.verb = 0
    results = []
    subnet = '192.168.207.41'
    start_time = time.time()
    ports = range(1, 1024)
    ip_list = ip_range(subnet)
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count()*10)
    active_ips = ping(subnet)
    for ip_addr in active_ips:
        print('{} is up, starting scan'.format(ip_addr))
        TCP_stealth_scan(subnet, ports)
#        results.append(result)
#    for result in results:
#        for r in result:
#            r.wait()
#        for result in filter(lambda i : i.get() != None, results):
#            print('{}'.format(result.get()[0]))
#        duration = time.time() - start_time
#        print('{0} scan completed in {1}'.format(ip_addr, duration))
#        print('{0} closed ports in {1} total ports scanned'.format(closed, len(ports)))
