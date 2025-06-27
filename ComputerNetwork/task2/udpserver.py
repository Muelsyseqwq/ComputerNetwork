
import time
import threading
import random
import struct
import socket
import queue
import sys
# 标志位
mySYN = 0x8000
myACK = 0x4000
myFIN = 0x2000
myDATA = 0x1000

HEADER_FORMAT = '!III H'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def crc_checksum(data: bytes, poly=0x1021, init=0xFFFF) -> int: #crc冗余校验
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if (crc & 0x8000):
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc & 0x0FFF

def create_packet(seq, ack, pkt_num, flags, payload=b''): #创建数据包
    header_without_checksum = struct.pack(HEADER_FORMAT, seq, ack, pkt_num, flags)
    checksum = crc_checksum(header_without_checksum + payload)
    flags_with_checksum = flags | checksum
    packet = struct.pack(HEADER_FORMAT, seq, ack, pkt_num, flags_with_checksum) + payload
    return packet

def unpack_header(header): #解封装头部
    seq, ack, pkt_num, flags_with_checksum = struct.unpack(HEADER_FORMAT, header)
    flags = flags_with_checksum & 0xF000
    checksum = flags_with_checksum & 0x0FFF
    return seq, ack, pkt_num, flags, checksum

def verify_checksum(data):
    if len(data) < HEADER_SIZE:
        return False
    seq, ack, pkt_num, flags_with_checksum = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    recv_flags = flags_with_checksum & 0xF000
    recv_checksum = flags_with_checksum & 0x0FFF
    header_without_checksum = struct.pack(HEADER_FORMAT, seq, ack, pkt_num, recv_flags)
    cal_checksum = crc_checksum(header_without_checksum + data[HEADER_SIZE:])
    return cal_checksum == recv_checksum

class ClientHandler(threading.Thread):
    def __init__(self, sock, client_addr, loss_rate=0.2, corruption_rate=0.05):
        super().__init__()
        self.sock = sock
        self.client_addr = client_addr
        self.loss_rate = loss_rate
        self.corruption_rate = corruption_rate

        self.conn_established = False
        self.expected_seq = 0
        self.total_packets = 0
        self.server_isn = random.randint(0, 0xffffffff)

        self.queue = queue.Queue()
        self.active = True

        # 以下用于挥手时的状态管理
        self.waiting_for_last_ack = False
        self.last_fin_sent_time = 0
        self.fin_retry_count = 0
        self.max_fin_retries = 5
        self.fin_packet = None

        print(f"新的连接来自 {client_addr}, 丢包率模拟: {loss_rate * 100}%")

    def run(self):
        while self.active:
            try:
                data = self.queue.get(timeout=0.1)
                self.process_packet(data)
            except queue.Empty:
                # 定时检测最后挥手的ACK,超时重发FIN 这里最多重发5次 因为可能客户端已经关闭了再发也没用
                if self.waiting_for_last_ack:
                    now = time.time()
                    if now - self.last_fin_sent_time > 0.3:
                        if self.fin_retry_count < self.max_fin_retries:
                            self.sock.sendto(self.fin_packet, self.client_addr)
                            print(f"[{time.strftime('%H:%M:%S')}] 超时未收到最后ACK，重发 FIN 第{self.fin_retry_count + 1}次")
                            self.fin_retry_count += 1
                            self.last_fin_sent_time = now
                        else:
                            print(f"[{time.strftime('%H:%M:%S')}] 重发 FIN 超过最大次数，关闭连接")
                            self.active = False

        print(f"与{self.client_addr}的连接已关闭")

    def process_packet(self, data): #处理数据包
        if len(data) < HEADER_SIZE:
            return

        header = data[:HEADER_SIZE]
        payload = data[HEADER_SIZE:]
        data_len = len(payload)
        current_time = time.strftime("%H:%M:%S")

        # 模拟包损坏
        if random.random() < self.corruption_rate:
            pos = random.randint(0, len(data) - 1)
            data = data[:pos] + bytes([data[pos] ^ 0xFF]) + data[pos + 1:]
            print(f"模拟包损坏: 修改了位置 {pos} 的字节")

        #损坏就check_sum出错了
        if not verify_checksum(data):
            print(f"Error: [{current_time}] 校验和失败! 数据包来自{self.client_addr}!")
            header = create_packet(0, self.expected_seq, 0, myACK)
            self.sock.sendto(header, self.client_addr)
            print(f"[{current_time}] 发送重复 ACK 到 {self.client_addr}, ack={self.expected_seq}")
            return

        seq, ack, pkt_num, flags, checksum = unpack_header(header)

        #第一次握手
        if flags & mySYN and not self.conn_established:
            print(f"[{current_time}] 收到 {self.client_addr} 的 SYN, seq = {seq}")
            header = create_packet(self.server_isn, seq + 1, 0, mySYN | myACK)
            self.sock.sendto(header, self.client_addr)
            print(f"[{current_time}] 发送 SYN-ACK 到 {self.client_addr}, seq = {self.server_isn}, ack = {seq + 1}")

        #第三次握手
        elif flags & myACK and not self.conn_established and ack == self.server_isn + 1:
            self.conn_established = True
            self.expected_seq = 0
            print(f"[{current_time}] 和 {self.client_addr} 三次握手完成，连接已建立！")

        #处理数据
        elif flags & myDATA and self.conn_established:
            if random.random() < self.loss_rate:
                print(f"Error: [{current_time}] 接受{self.client_addr}数据时发生丢包 (seq = {seq})")
                return
            #必须顺序否则重传
            if seq == self.expected_seq:
                self.expected_seq += data_len
                self.total_packets += 1
                start_byte = seq
                end_byte = seq + data_len - 1
                print(f"[{current_time}] 收到来自 {self.client_addr} 的数据包 {pkt_num} ({start_byte}~{end_byte}字节)")

                header = create_packet(0, self.expected_seq, 0, myACK)
                self.sock.sendto(header, self.client_addr)
                print(f"[{current_time}] 发送 ACK 到 {self.client_addr}, ack={self.expected_seq}")

            else:
                header = create_packet(0, self.expected_seq, 0, myACK)
                self.sock.sendto(header, self.client_addr)
                print(f"[{current_time}] 发送重复 ACK 到 {self.client_addr}, ack={self.expected_seq}")

        elif flags & myFIN:
            print(f"[{current_time}] 收到 {self.client_addr} 的 FIN")
            # 发送ACK确认第二次挥手
            header = create_packet(0, seq + 1, 0, myACK)
            self.sock.sendto(header, self.client_addr)
            print(f"[{current_time}] 发送 ACK 到 {self.client_addr}, ack={seq + 1}")

            # 发送 FIN，开始等待最后ACK
            self.fin_packet = create_packet(0, seq + 1, 0, myFIN)
            self.sock.sendto(self.fin_packet, self.client_addr)
            print(f"[{current_time}] 发送 FIN 到 {self.client_addr}, 等待最后 ACK")

            self.last_fin_sent_time = time.time()
            self.fin_retry_count = 0
            self.waiting_for_last_ack = True

        elif flags & myACK and self.waiting_for_last_ack:
            # 判断是否是最后ACK，确认ACK号等于FIN序号+1（这里FIN序号是0，所以ACK==1）
            if ack == 1:
                print(f"[{current_time}] 收到来自 {self.client_addr} 的最后 ACK，连接关闭")
                self.get_last_ack = True
                self.conn_established = False
                self.waiting_for_last_ack = False
                self.active = False


    def add_packet(self, data):
        self.queue.put(data)

    def close(self):
        self.active = False


class UDPServer:
    def __init__(self, port, loss_rate=0.2,corruption_rate = 0.05):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', port))

        self.loss_rate = loss_rate
        self.client_handlers = {}
        self.port = port
        self.corruption_rate = corruption_rate
        print(f"UDP 服务器启动, 端口: {port}, 丢包率: {loss_rate * 100}%")

    def run(self):
        print(f"服务器监听在{self.port}端口,等待连接....")
        try:
            while True:
                data, address = self.sock.recvfrom(2048)
                if address not in self.client_handlers:
                    handler = ClientHandler(self.sock, address, self.loss_rate,self.corruption_rate)
                    handler.daemon = True
                    handler.start()
                    self.client_handlers[address] = handler
                self.client_handlers[address].add_packet(data)
        except KeyboardInterrupt:
            print("\n服务器关闭中...")
            for handler in self.client_handlers.values():
                handler.close()
        finally:
            self.sock.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python udpserver.py <端口> [丢包率] [数据损坏率]")
        print("示例: python udpserver.py 6666 0.03 0.05")
        sys.exit(1)

    port = int(sys.argv[1])
    loss_rate = float(sys.argv[2]) if len(sys.argv) > 2 else 0.2
    corruption_rate = float(sys.argv[3]) if len(sys.argv) > 3 else 0.05
    # port = 6666
    # loss_rate = 0.03
    # corruption_rate = 0.03
    server = UDPServer(port, loss_rate,corruption_rate)
    server.run()