import random
from utils.packet import Client, Server, TCPFlow
from scapy.all import Ether, IP, TCP, UDP


if __name__ == '__main__':
    pkt = Ether() / IP(src='0.0.0.1', dst='1.1.1.1') / TCP(sport=1, dport=2, flags="FA", seq=0, ack=1)
    if UDP in pkt:
        print(pkt[TCP])
    else:
        print('no tcp')
