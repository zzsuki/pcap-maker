"""
基于scapy实现udp收发的功能
"""
from scapy.all import Ether, IP, UDP
from utils.packet.base import FlowController
import logging


class UDPFlow(FlowController):
    """UDPFlow is a class to generate UDP packets"""

    def send(self, payload=b"", direction=0):
        if direction == 0:
            msg = Ether(src=self.client.mac, dst=self.server.mac)/IP(src=self.client.ip, dst=self.server.ip)/UDP(sport=self.client.port, dport=self.server.port)/payload
            self._packet_bucket.append(msg)
        elif direction == 1:
            msg = Ether(src=self.server.mac, dst=self.client.mac)/IP(src=self.server.ip, dst=self.client.ip)/UDP(sport=self.server.port, dport=self.client.port)/payload
            self._packet_bucket.append(msg)
        else:
            logging.warning("Param `direction` must be 0 or 1, 0 for client to server, 1 for server to client. This call will make no effect on packet_bucket.")
