from scapy.all import *
from rich import print as rprint

class Scanner:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
    
    def ip(self):
        return self.ip
    
    def port(self):
        return self.port
    
   
    def ping(self):
        self.ping_packet = IP(dst=self.ip)/ICMP()
        try:
            self.ping_response = sr1(self.ping_packet, timeout=1, verbose=0)
            return self.ping_response
        except:
            rprint("[bold red]Error: Scan requires sudo, exiting....")
            exit()
    
    def syn(self):
        self.syn_packet = IP(dst=self.ip)/TCP(dport=self.port, flags='S')
        self.rest_packet = IP(dst=self.ip)/TCP(dport=self.port, flags='R')

        try:
            self.response = sr1(self.syn_packet, verbose=0, timeout=1)
            self.responeFlag = self.response.sprintf("%TCP.sport% %TCP.flags%")
            self.responeFlag = self.responeFlag.split(" ")
            if self.responeFlag[1] == "SA":
                sr1(self.rest_packet, verbose=0, timeout=1)
            return self.responeFlag
        except:
            return None
    
    def connect(self):
        try:
            self.sport = random.randint(1024,65535)

            self.target_ip = IP(dst=self.ip)

            self.syn = TCP(dport=self.port, sport=self.sport, flags="S", seq=100)

            self.syn_packet = sr1(self.target_ip/self.syn, verbose=0, timeout=1)

            self.rest_packet = TCP(dport=self.port, sport=self.sport, flags='R')

            self.responeFlag = self.syn_packet.sprintf("%TCP.sport% %TCP.flags%")

            self.responeFlag = self.responeFlag.split(" ")

            if self.responeFlag[1] == "SA":
                self.my_ack = self.syn_packet.seq + 1

                self.ack_packet= TCP(dport=self.port, sport=self.sport, flags="A", seq=101, ack=self.my_ack)

                send(self.target_ip/self.ack_packet, verbose=0)

                send(self.target_ip/self.rest_packet, verbose=0)
            

            return self.responeFlag
        except:
            return None
