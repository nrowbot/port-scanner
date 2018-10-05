# Port Scanner  
  
This port scanner can be run from the terminal. Typing in
`python3 scan.py -h` will return the various options that
can be added. In general, this scanner can be used on an
IP address or range of IP addresses to perform a ping sweep,
TCP stealth scan, UDP scan, or traceroute. A pdf can also be
generated.  
  
### Basic Usage  
  
The following will perform a TCP scan on ports 1 through 500 on
the 192.168.207.0/24 subnet:  
  
`python3 scan.py -sT -p 1-500 192.168.207.0/24`  
  
The following will perform a UDP scan on the default port 1 through
1000 on 192.168.207.41:  
  
`python3 scan.py -sU 192.168.207.41`  
  
The following will perform a ping sweep on the 192.168.207.0/24
subnet:  
  
`python3 scan.py -ps 192.168.207.0-255`  
  
The following will perform a traceroute on 192.168.207.42:  
  
`python3 scan.py -t 192.168.207.42`  
  
### Requirements  
  
This scanner was built on Kali linux. It uses python 3 and requires
that the following packages be installed with pip3:  
  
argparse  
netaddr  
scapy  
tabulate  
fpdf  
