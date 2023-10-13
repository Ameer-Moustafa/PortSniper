from scapy.all import *


target_ip = IP(dst="45.33.32.156")

syn = TCP(dport=80, flags="S", seq=100)

syn_packet = sr1(target_ip/syn)

syn_packet.show()