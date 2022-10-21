import nmap
import socket
from scapy.layers import inet
import scapy.all as scapy
import os
import requests


def deal_with_packets(x):
    os.system("cls")
    ips = x.sprintf("%IP.proto% packets from %IP.src% to %IP.dst%")
    print(requests.post('http://127.0.0.1:8000/get_packets', data={"clientID":1, "data":ips, "country": x.sprintf("%IP.dst%")}))


def printPacket(packet):
    print(packet)


# initialize the port scanner
nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe",]
nmScan = nmap.PortScanner(nmap_search_path=nmap_path)
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# scan localhost for ports in range 21-443
nmScan.scan('127.0.0.1', '0-50')

for host in nmScan.all_hosts():
    print('Host : %s (%s)' % (host, nmScan[host].hostname()))
    print('State : %s' % nmScan[host].state())
    for proto in nmScan[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)

        lport = nmScan[host][proto].keys()
        for port in lport:
            print('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))
packet = inet.Ether()/inet.IP()/inet.TCP()
for p in packet:
    a = p.show(dump=True)
    print(type(a))
    print(a)


scapy.sniff(iface=None, store=False, prn=deal_with_packets)

