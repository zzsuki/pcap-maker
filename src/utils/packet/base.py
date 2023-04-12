"""
与packet构建相关的基础类
"""
from typing import List
from scapy.all import wrpcap


class Member:
    def __init__(self, ip, port, mac):
        self.ip = ip
        self.port = port
        self.mac = mac
        self.ack = 0
        self.seq = 0

    def __str__(self):
        return f"{self.ip}:{self.port}"

    def __repr__(self):
        return f"{self.ip}:{self.port}"


class Client(Member):
    pass


class Server(Member):
    pass


class FlowController:
    def __init__(self, client: Client, server: Server):
        self.client = client
        self.server = server
        self._packet_bucket: List = []

    def dump(self, filename):
        """Dump the packet bucket to a pcap file"""
        wrpcap(filename, self._packet_bucket)
