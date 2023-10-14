from scapy.all import *


target_ip = IP(dst="45.33.32.156")

syn = TCP(dport=80, sport=4444, flags="S", seq=100)

syn_packet = sr1(target_ip/syn)

my_ack = syn_packet.seq + 1

ack_packet= TCP(dport=80, sport=4444, flags="A", seq=101, ack=my_ack)
final_packet = send(target_ip/ack_packet)

final_packet.show()