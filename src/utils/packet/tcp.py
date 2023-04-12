"""
基于scapy为tcp flow提供自动握手和挥手的操作，用户只需要传入通信的payload即可
"""

from scapy.all import Ether, IP, TCP
from utils.packet.base import FlowController, Client, Server, Member
import random
import logging

# seq: 记录当前host的序列,一般要和对端保持一致
# ack：记录当前host下一个希望收到的对方的seq
# 连接初建时，随机生成一个seq, seq范围为[0, 2 ** 32]，超过时会自动归零


MAX_SEQ = 2 ** 32


class TCPFlow(FlowController):
    """TCPFlow is a class to generate TCP packets"""

    def __init__(self, client: Client, server: Server):
        super().__init__(client, server)
        self._handshake()

    def _handshake(self):
        """Generate handshake packet"""
        # syn
        self.client.seq = random.randint(0, MAX_SEQ)
        self.client.ack = 0
        syn = Ether(src=self.client.mac, dst=self.server.mac)/IP(src=self.client.ip, dst=self.server.ip)/TCP(sport=self.client.port, dport=self.server.port, flags="S", seq=self.client.seq)
        self._packet_bucket.append(syn)
        # syn_ack
        self.server.seq = self.client.seq
        self.server.ack = self.client.seq + 1
        syn_ack = Ether(src=self.server.mac, dst=self.client.mac)/IP(src=self.server.ip, dst=self.client.ip)/TCP(sport=self.server.port, dport=self.client.port, flags="SA", seq=self.server.seq, ack=self.server.ack)
        self._packet_bucket.append(syn_ack)
        # ack
        self.client.seq = self.server.ack
        self.client.ack = self.server.seq + 1
        ack = Ether(src=self.client.mac, dst=self.server.mac)/IP(src=self.client.ip, dst=self.server.ip)/TCP(sport=self.client.port, dport=self.server.port, flags="A", seq=self.client.seq, ack=self.client.ack)
        self._packet_bucket.append(ack)

    def send(self, payload=b"", direction=0):
        """send data in given direction"""
        # 不论从c到s，还是从s到c,每次发送前，都需要更新自己的seq为对端的ack，对方在收到包后，要根据包长设置新的ack; 但是对于ack包，不需要更新seq，因为ack包不携带数据
        # pylint: disable=fixme
        # TODO: 增加超出范围后的重置机制
        if direction == 0:
            self.client.seq = self.server.ack
            pa = Ether(src=self.client.mac, dst=self.server.mac)/IP(src=self.client.ip, dst=self.server.ip)/TCP(sport=self.client.port, dport=self.server.port, flags="PA", seq=self.client.seq, ack=self.client.ack)/payload
            self.server.ack += len(payload)

            self.server.seq = self.client.ack
            ack = Ether(src=self.server.mac, dst=self.client.mac)/IP(src=self.server.ip, dst=self.client.ip)/TCP(sport=self.server.port, dport=self.client.port, flags="A", seq=self.server.seq, ack=self.server.ack)

            self._packet_bucket.append(pa)
            self._packet_bucket.append(ack)
        elif direction == 1:
            self.server.seq = self.client.ack
            pa = Ether(src=self.server.mac, dst=self.client.mac)/IP(src=self.server.ip, dst=self.client.ip)/TCP(sport=self.server.port, dport=self.client.port, flags="PA", seq=self.server.seq, ack=self.server.ack)/payload
            self.client.ack += len(payload)

            self.client.seq = self.server.ack
            ack = Ether(src=self.client.mac, dst=self.server.mac)/IP(src=self.client.ip, dst=self.server.ip)/TCP(sport=self.client.port, dport=self.server.port, flags="A", seq=self.client.seq, ack=self.client.ack)

            self._packet_bucket.append(pa)
            self._packet_bucket.append(ack)
        else:
            logging.warning("Param `direction` must be 0 or 1, 0 for client to server, 1 for server to client. This call will make no effect on packet_bucket.")

    def _close(self):
        """Generate close packet"""
        # fin_ack
        self.client.seq = self.server.ack
        fin_ack = Ether(src=self.client.mac, dst=self.server.mac)/IP(src=self.client.ip, dst=self.server.ip)/TCP(sport=self.client.port, dport=self.server.port, flags="FA", seq=self.client.seq, ack=self.client.ack)
        self._packet_bucket.append(fin_ack)
        self.server.ack = self.client.seq + 1
        # ack
        self.server.seq = self.client.ack
        ack = Ether(src=self.server.mac, dst=self.client.mac)/IP(src=self.server.ip, dst=self.client.ip)/TCP(sport=self.server.port, dport=self.client.port, flags="A", seq=self.server.seq, ack=self.server.ack)
        self._packet_bucket.append(ack)
        # fin_ack
        self.server.seq = self.client.ack
        fin_ack = Ether(src=self.server.mac, dst=self.client.mac)/IP(src=self.server.ip, dst=self.client.ip)/TCP(sport=self.server.port, dport=self.client.port, flags="FA", seq=self.server.seq, ack=self.server.ack)
        self._packet_bucket.append(fin_ack)
        self.client.ack += 1
        # ack
        self.client.seq = self.server.ack
        ack = Ether(src=self.client.mac, dst=self.server.mac)/IP(src=self.client.ip, dst=self.server.ip)/TCP(sport=self.client.port, dport=self.server.port, flags="A", seq=self.client.seq, ack=self.client.ack)
        self._packet_bucket.append(ack)

    def dump(self, filename):
        self._close()
        return super().dump(filename)

if __name__ == '__main__':
    ...
