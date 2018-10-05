import time
import multiprocessing
import logging
from netaddr import IPNetwork
from scapy.all import *
from tabulate import tabulate

DEBUG = 1
#logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

def debug(debug_string):
    if DEBUG:
        print(debug_string)

def ip_range(ip_range):
    ip_list = []
    for ip_addr in IPNetwork(ip_range):
        ip_list.append(str(ip_addr))
    return ip_list
        
def TCP_stealth_scan(ip_range, ports):
    active_ports = []
    source_port = RandShort()
    packet = IP(dst=ip_range)/TCP(sport=source_port, dport=ports, flags='S')
    ans, unans = sr(packet, timeout=2, verbose=False)
    # sr(IP(dst=ip_range)/TCP(sport=source_port, dport=ports, flags='R'), timeout=2)
    for answer in ans:
        if answer[1][1].flags == 'SA':
            active_ports.append(int(answer[1].sport))
    sr(IP(dst=ip_range)/TCP(sport=source_port, dport=active_ports, flags='R'), timeout=2, verbose=False)
    return active_ports
    
def ping(ip_range):
    active_ips = []
    packet = IP(dst=ip_range)/ICMP()
    ans, unans = sr(packet, timeout=2, verbose=False)
    for answer in ans:
        active_ips.append(answer[1].src)
    return active_ips

def print_results(results):
    hdrs = ['Host','Active Ports']
    data = []
    for ip_addr, ports in results.items():
        if ports:
            data.append([ip_addr, ports[0]])
            for i in range(1,(len(ports)-1)):
                data.append(['',ports[i]])
    print(tabulate(data, headers=hdrs))

def traceroute(hostnames):
    destinations = set()
    trace = {}
    hdrs = ['Hop', 'IP']
    data = []
    ans, unans = sr(IP(dst=hostnames, ttl=(1,30), id=RandShort())/TCP(flags=0x2), timeout=2, verbose=0)
    for send, rcv in ans:
        destinations.add(send.dst)
    for ip_addr in destinations:
        trace[ip_addr] = []
    for send, rcv in ans:
        if(rcv.src not in trace[send.dst]):
            trace[send.dst].append(rcv.src)
    for ip_addr in destinations:
        print('Traceroute to: {}'.format(ip_addr))
        hops = 1
        for ips in trace[ip_addr]:
            data.append([hops, ips])
            hops += 1
    print(tabulate(data, headers=hdrs))


if __name__ == '__main__':
    results = {}
    subnet = '192.168.207.0/24'
    traceroute('google.com')
    start_time = time.time()
    ports = range(1, 1024)
    ip_list = ip_range(subnet)
    active_ips = ping(subnet)
    print('{} hosts are active, starting scan'.format(len(active_ips)))
    for ip_addr in active_ips:
        results[ip_addr] = TCP_stealth_scan(ip_addr, ports)
    print_results(results)
