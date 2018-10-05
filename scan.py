import argparse
from netaddr import IPNetwork, IPAddress
from scapy.all import *
from tabulate import tabulate
from fpdf import FPDF

def ip_range(ip_range):
    # creates an ip range from the passed in argument
    ip_list = []
    try:
        dash_range = re.search('-', ip_range)
        cidr_range = re.search('/', ip_range)
        if dash_range is not None or cidr_range is not None:
            for ip_addr in IPNetwork(ip_range):
                ip_list.append(str(ip_addr))
            return ip_list
        elif IPAddress(ip_range):
            return str(ip_range)
    except ValueError:
        print('Not a valid target IP or range')
        print_usage()
        
def TCP_stealth_scan(ip_range, ports):
    # uses scapy to perform a TCP stealth scan, stores the active ports for the
    # address that the scan is run on in a list and returns it
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

def UDP_scan(ip_range, ports):
    # uses scapy to perform a UDP scan, stores the active ports for the
    # address that the scan is run on in a list and returns it
    active_ports = []
    source_port = RandShort()
    for port in ports:
        packet = IP(dst=ip_range)/UDP(sport=source_port, dport=port)
        ans = sr(packet, timeout=2, verbose=0)
        if ans is None:
            active_ports.append('{} Open|Filtered'.format(port))
        elif(ans):
            answer = str(ans[0]).split()
            udp = answer[2].split(':')[1]
            if udp:
                active_ports.append('{} Filtered'.format(port))
    return active_ports
    
def ping(ip_range):
    # uses scapy to ping ip addresses
    active_ips = []
    packet = IP(dst=ip_range)/ICMP()
    ans, unans = sr(packet, timeout=2, verbose=False)
    for answer in ans:
        active_ips.append(str(answer[1].src))
    return active_ips

def traceroute(hostnames):
    # uses scapy to perform a traceroute on ip addresses
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
    return [hdrs, data]

def print_scan_results(results):
    # prints the results of the TCP or UDP scan
    hdrs = ['Host','Active Ports']
    data = []
    for ip_addr, ports in results.items():
        if ports:
            data.append([ip_addr, ports[0]])
            for i in range(1,(len(ports)-1)):
                data.append(['',ports[i]])
        else:
            data.append([ip_addr, ''])
    print(tabulate(data, headers=hdrs))
    return [hdrs, data]

def print_ping_results(results):
    # prints the results of the ping sweep
    hdrs = ['Active Hosts']
    data = []
    for ip_addr in results:
        data.append([ip_addr])
    print(tabulate(data, headers=hdrs))
    return [hdrs, data]

def create_parser():
    # creates the terminal argument parser and captures the user's input
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='host/ip or ip range to scan in cidr notation or in the form 192.168.207.2-100')
    parser.add_argument('-sT', dest='tcp', action='store_true', help='performs a TCP stealth scan on the target')
    parser.add_argument('-sU', dest='udp', action='store_true', help='performs a UDP scan on the target')
    parser.add_argument('-p', '--port', dest='port', help='port(s) to scan, e.g. 1-100 if a range')
    parser.add_argument('-ps', '--pingsweep', dest='ps', action='store_true', help='performs a ping sweep')
    parser.add_argument('-t', '--traceroute', dest='trace', action='store_true', help='performs a traceroute on the host')
    parser.add_argument('-r', '--report', dest='pdf', action='store_true', help='prints the results to a pdf report')
    args = parser.parse_args()
    return args

def target_parser(target):
    # ensures that a target is entered or prints the proper usage
    if target is None:
        print('No target was entered')
        print_usage()
    return target

def ports_parser(ports):
    # ensures that ports are input in the form 1,600-100 and returns
    # an integer list of ports
    if ports is None:
        print('Default ports will be used')
        return range(1, 1000)
    else:
        try:
            if(re.search('-', ports) is not None):
                ports = ports.split('-')
                return range(int(ports[0]), int(ports[1]))
            elif(re.search(',', ports) is not None):
                ports = ports.split(',')
                int_ports = []
                for port in ports:
                    int_ports.append(int(port))
                return int_ports
            else:
                return int(ports)
        except ValueError:
            print('Please enter ports as integers')
            print_usage()

def print_usage():
    print('Usage: python3 scapy.py <target> -sT -p <port(s)>')
    sys.exit()

def print_pdf(headers, data):
    # prints to a pdf report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Courier', 'I', 14)
    pdf.set_draw_color(255, 255, 255)
    for header in headers:
        pdf.cell(len(header)*4, 10, str(header), 1)
    for elements in data:
        pdf.ln()
        for element in elements:
            pdf.cell(len(str(element))*4, 10, str(element), 1)
    pdf.output('results.pdf')

if __name__ == '__main__':
    results = {}
    args = create_parser()
    target = target_parser(args.target)
    if args.tcp:
        ports = ports_parser(args.port)
        active_ips = ping(target)
        print('{} hosts are active, starting scan'.format(len(active_ips)))
        for ip_addr in active_ips:
            results[ip_addr] = TCP_stealth_scan(ip_addr, ports)
        pdf_results = print_scan_results(results)
        if args.pdf:
            print_pdf(pdf_results[0], pdf_results[1])
    if args.udp:
        ports = ports_parser(args.port)
        active_ips = ping(target)
        print('{} hosts are active, starting scan'.format(len(active_ips)))
        for ip_addr in active_ips:
            results[ip_addr] = UDP_scan(ip_addr, ports)
        pdf_results = print_scan_results(results)
        if args.pdf:
            print_pdf(pdf_results[0], pdf_results[1])
    if args.ps:
        active_ips = ping(target)
        pdf_results = print_ping_results(active_ips)
        if args.pdf:
            print_pdf(pdf_results[0], pdf_results[1])
    if args.trace:
        results = traceroute(target)
        if args.pdf:
            print_pdf(pdf_results[0], pdf_results[1])
