import scapy
while(True):
    packet =scapy.IP(dst="127.0.0.1")/scapy.ICMP()
    response = scapy.srl(packet)