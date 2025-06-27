import socket
import struct
import random #用于模拟丢包
import sys
import time
import threading
import queue
import pandas as pd
from isapi.isapicon import HSE_EXEC_URL_DISABLE_CUSTOM_ERROR

# 我的header格式
#! 网络协议 大端
# 序列号 I (4B)
# 确认号 I (4B)
# 分组号 I (4B)
# 标志位 4bit
# 校验和 12 bit 两者一共 2 B
HEADER_FORMAT = '!III H'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
# print(HEADER_SIZE) #14

#标志位 这里我们只用高4位 低12位用于checksum
mySYN = 0x8000 #1000 0000 0000 0000
myACK = 0x4000 #0100 0000 0000 0000
myFIN = 0x2000 #0010 0000 0000 0000
myDATA = 0x1000 #0001 0000 0000 0000

def crc_checksum(data: bytes, poly=0x1021, init=0xFFFF) -> int:
    '''实现校验和计算 CRC 冗余校验'''
    #poly 为生成多项式 data 是 10个字节
    crc = init # 1111 1111 1111 1111
    for byte in data:
        crc ^= byte << 8  # 将byte移到高8位
        for _ in range(8):
            if (crc & 0x8000):  # 如果最高位是1
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc & 0x0FFF


def create_packet(seq,ack,pkt_num,flags,payload = b''):
    '''创建header'''
    #先创建不带校验和的头部
    header_without_checksum = struct.pack(HEADER_FORMAT, seq,ack,pkt_num,flags) #二进制字节流（bytes)
    checksum = crc_checksum(header_without_checksum + payload)
    # print(header_without_checksum)
    flags_with_checksum  = flags | checksum

    packet = struct.pack(HEADER_FORMAT, seq, ack, pkt_num,flags_with_checksum)
    packet += payload
    return packet

def unpack_header(header):
    '''解析header'''
    seq,ack,pkt_num,flags_with_checksum = struct.unpack(HEADER_FORMAT, header)
    flags = flags_with_checksum & 0xF000
    checksum = flags_with_checksum & 0x0FFF
    return seq,ack,pkt_num,flags,checksum

def verify_checksum(data):

    '''验证校验和'''
    #对方发过来的checksum 我自己算一遍检查一下

    if len(data) < HEADER_SIZE:
        return False

    #解析头部
    seq,ack,pkt_num,flags_with_checksum =struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    recv_flags = flags_with_checksum & 0xF000
    recv_checksum = flags_with_checksum & 0x0FFF

    #对收到的进行打包
    header_without_checksum = struct.pack(HEADER_FORMAT, seq, ack,pkt_num, recv_flags)

    #自己计算一下校验和
    cal_checksum = crc_checksum(header_without_checksum + data[HEADER_SIZE:])
    # print(cal_checksum ,recv_checksum)
    return cal_checksum == recv_checksum

class GBNClient:
    def __init__(self, server_ip, server_port , total_packets=30, window_size=400):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = (server_ip, server_port)
        self.total_packets = total_packets
        self.window_size = window_size
        self.base = 0
        self.next_seq = 0
        self.client_isn = random.randint(0, 0xffffffff)
        self.packets = {}  # 存储所有发送的包
        self.rtt_list = []

        self.total_sent = 0 #存储总的发送包个数
        self.estimated_rtt = 0 #模拟书上的超时重传
        self.dev_rtt = 0
        self.timeout = 0.3
        self.conn_established = False
        # self.ack_count = {}
        print(f"客户端启动, 将发送 {total_packets} 个数据包, 窗口大小: {window_size} 字节")

    def three_handshake(self):
        '''三次握手'''
        header = create_packet(self.client_isn, 0, 0,mySYN) #控制包（SYN/ACK/FIN）：packet_num设为0
        self.sock.sendto(header, self.server_address) #发送FIN 第一次握手
        current_time = time.strftime("%H:%M:%S")
        print(f"[{current_time}] 发送 SYN (seq={self.client_isn})")

        start_time = time.time() #接收ACK 第二次握手
        while True:
            try:
                self.sock.settimeout(2)
                data, addr = self.sock.recvfrom(1024)
                if not verify_checksum(data):
                    print(f"[{current_time}] 校验和失败, 丢弃数据包")
                    continue
                seq, ack, pkt_num,flags, checksum = unpack_header(data[:HEADER_SIZE])
                current_time = time.strftime("%H:%M:%S")
                if flags & mySYN and flags & myACK and ack == self.client_isn + 1:
                    handshake_rtt = (time.time() - start_time) * 1000
                    server_time = time.strftime("%H:%M:%S")
                    print(
                        f"[{current_time}] 收到 SYN-ACK, seq={seq}, ack={ack}, RTT={handshake_rtt:.2f}ms, 服务器时间: {server_time}")
                    break
            except socket.timeout:
                current_time = time.strftime("%H:%M:%S")
                print(f"Error: [{current_time}] 超时, 重新发送 SYN")
                self.sock.sendto(header, self.server_address)
        #发送ACK 第三次握手
        header = create_packet(self.client_isn + 1, seq + 1,0, myACK)
        self.sock.sendto(header, self.server_address)
        current_time = time.strftime("%H:%M:%S")
        print(f"[{current_time}] 发送 ACK, 连接建立!")
        self.conn_established = True

    def run(self):
        self.three_handshake()

        print(f"\n开始数据传输, 固定窗口大小: {self.window_size} 字节")
        packet_num = 1
        window_end = self.base

        while packet_num <= self.total_packets or window_end > self.base: #使用类似tcp的窗口滑动,便于处理不同大小的包
            packets_in_window = 0
            while window_end < self.base + self.window_size and packet_num <= self.total_packets:
                packet_size = random.randint(40, 80)

                if window_end + packet_size > self.base + self.window_size: #超过窗口就不发了
                    break

                start_byte = window_end
                end_byte = window_end + packet_size - 1
                window_end = end_byte + 1

                #模拟封装的数据
                payload = struct.pack('!I', packet_num) + b'\0' * (packet_size - 4)
                packet = create_packet(start_byte, 0, packet_num,myDATA,payload)

                self.sock.sendto(packet, self.server_address)
                self.total_sent += 1

                sent_time = time.time()
                self.packets[packet_num] = {
                    'start': start_byte,
                    'end': end_byte,
                    'sent_time': sent_time,
                    'acked': False,  # 初始未确认
                    'size': packet_size,
                    'rtt': None,  # 初始无RTT值
                    'ack_time': None  # 添加确认时间字段
                }

                current_time = time.strftime("%H:%M:%S")
                print(f"[{current_time}] 发送包 {packet_num} ({start_byte}~{end_byte}字节), "
                      f"大小: {packet_size}字节, 窗口使用: {window_end - self.base}/{self.window_size}字节")

                packet_num += 1
                packets_in_window += 1 #维护窗口内包的个数

            if packets_in_window > 0:
                print(f"当前窗口发送包数: {packets_in_window}, 使用字节: {window_end - self.base}")

            self.receive_ack() #接收ack

            unacked_packets = [p for p in self.packets.values() if not p['acked']] #重传 超时重传
            if unacked_packets:
                oldest_time = min(p['sent_time'] for p in unacked_packets)
                if time.time() - oldest_time > self.timeout:
                    current_time = time.strftime("%H:%M:%S")
                    print(f"[{current_time}] 超时 ({self.timeout * 1000:.0f}ms), 重传窗口中所有数据包")

                    for pkt_num, info in self.packets.items():
                        if not info['acked']:
                            payload = struct.pack('!I', pkt_num) + b'\0' * (info['size'] - 4)
                            packet = create_packet(info['start'], 0,pkt_num,myDATA,payload)

                            self.sock.sendto(packet, self.server_address)
                            self.total_sent += 1
                            info['sent_time'] = time.time()
                            print(f"重传包 {pkt_num} ({info['start']}~{info['end']}字节)")
        '''四次挥手'''
        fin_seq = window_end
        header = create_packet(fin_seq , 0,0, myFIN)
        self.sock.sendto(header, self.server_address)
        current_time = time.strftime("%H:%M:%S")
        print(f"[{current_time}] 发送 FIN (seq={fin_seq})")

        start_time = time.time()
        while True:
            try:
                self.sock.settimeout(1)
                data, addr = self.sock.recvfrom(1024)
                if not verify_checksum(data[:HEADER_SIZE]):
                    print("Error:  校验和失败, 丢弃数据包 ")
                    continue
                seq, ack, pkt_num,flags, _ = unpack_header(data[:HEADER_SIZE])
                current_time = time.strftime("%H:%M:%S")
                if flags & myACK and ack == fin_seq + 1:
                    print(f"[{current_time}] 收到 ACK（第二次挥手），ack={ack}")
                    break
            except socket.timeout:
                print(f"[{current_time}] 超时，重新发送 FIN")
                self.sock.sendto(header, self.server_address)

        while True:
            try:
                self.sock.settimeout(5)
                data, addr = self.sock.recvfrom(1024)
                if not verify_checksum(data[:HEADER_SIZE]):
                    continue
                seq, ack, pkt_num,flags, _ = unpack_header(data[:HEADER_SIZE])
                current_time = time.strftime("%H:%M:%S")
                if flags & myFIN:
                    print(f"[{current_time}] 收到 FIN（第三次挥手）")
                    header = create_packet(ack, seq + 1, 0,myACK)
                    self.sock.sendto(header, self.server_address)
                    print(f"[{current_time}] 发送 ACK（第四次挥手）")
                    break
            except socket.timeout:
                print(f"[{current_time}] 等待 FIN 超时，继续等待...")

        self.print_stats()
        t1 = time.time()
        print("等待最后30s,避免服务器未收到第四次挥手的ACK!")
        while time.time() - t1 < 30:
            #处理没收到服务器最后一个ack
            # print("等待最后30s,避免服务器未收到第四次挥手的ACK!")
            try:
                data, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                # 超时没收到包，继续循环检查时间是否超时
                continue

            if not verify_checksum(data[:HEADER_SIZE]):
                continue
            seq, ack, pkt_num, flags, _ = unpack_header(data[:HEADER_SIZE])
            current_time = time.strftime("%H:%M:%S")
            if flags & myFIN:
                print(f"[{current_time}] 收到 重复的FIN（第三次挥手）")
                header = create_packet(ack, seq + 1, 0, myACK)
                self.sock.sendto(header, self.server_address)
                print(f"[{current_time}] 再次发送 ACK（第四次挥手）")
                t1 = time.time()
        self.sock.close()
        print("连接已关闭!")

    def receive_ack(self):
        try:
            self.sock.settimeout(0.1)
            data, addr = self.sock.recvfrom(1024)
            if len(data) < HEADER_SIZE:
                return False

            if not verify_checksum(data):
                print("Error: 校验和失败, 丢弃数据包!")
                return False

            seq, ack, pkt_num,flags, checksum = unpack_header(data[:HEADER_SIZE])
            current_time = time.strftime("%H:%M:%S")
            server_time = time.strftime("%H:%M:%S")

            if flags & myACK:
                if ack > self.base:
                    for pkt_num, info in self.packets.items():
                        if info['end'] < ack and not info['acked']:
                            ack_time = time.time()
                            rtt = (ack_time - info['sent_time']) * 1000
                            self.rtt_list.append(rtt)

                            # 更新包信息
                            info['acked'] = True
                            info['rtt'] = rtt
                            info['ack_time'] = ack_time

                            start_byte = info['start']
                            end_byte = info['end']
                            print(
                                f"[{current_time}] 包 {pkt_num} ({start_byte}~{end_byte}字节) 已确认, "
                                f"RTT={rtt:.2f}ms, 服务器时间: {server_time}")

                            # if len(self.rtt_list) >= 5:
                            #     avg_rtt = pd.Series(self.rtt_list[-5:]).mean()
                            #     self.timeout = max(0.05, min(1.0, 5 * avg_rtt / 1000))
                            #     print(
                            #         f"[{current_time}] 更新超时时间为 {self.timeout * 1000:.0f}ms (平均RTT: {avg_rtt:.2f}ms)")
                            #模拟书上的超时重传
                            if info['rtt'] is not None:
                                sample_rtt = info['rtt'] / 1000  # 转换为秒
                                if self.estimated_rtt is None:
                                    self.estimated_rtt = sample_rtt
                                    self.dev_rtt = sample_rtt / 2
                                else:
                                    alpha = 0.125
                                    beta = 0.25
                                    self.estimated_rtt = (1 - alpha) * self.estimated_rtt + alpha * sample_rtt
                                    self.dev_rtt = (1 - beta) * self.dev_rtt + beta * abs(
                                        sample_rtt - self.estimated_rtt)

                                self.timeout = max(0.005,
                                                   min(1.0, self.estimated_rtt + 4 * self.dev_rtt))  # 0.05s最小，1s最大限制

                                current_time = time.strftime("%H:%M:%S")
                                print(f"[{current_time}] 超时调整: EstRTT={self.estimated_rtt * 1000:.2f}ms, "
                                      f"DevRTT={self.dev_rtt * 1000:.2f}ms -> Timeout={self.timeout * 1000:.2f}ms")

                    self.base = ack
                    return True
        except socket.timeout:
            pass
        return False

    def print_stats(self):
        if not self.rtt_list:
            print("\n没有包被确认")
            return

        # 计算统计信息
        loss_count = self.total_sent - self.total_packets
        loss_rate = self.total_packets / self.total_sent if self.total_sent > 0 else 0.0

        # 提取所有已确认包的RTT值
        confirmed_rtts = [info['rtt'] for info in self.packets.values() if info['acked']]
        if not confirmed_rtts:
            print("\n没有包被确认")
            return

        s = pd.Series(confirmed_rtts)

        print("\n【传输统计汇总】")
        print(f"总发送包数: {self.total_sent}")
        print(f"总接收包数: {self.total_packets}")
        print(f"丢包率: {loss_rate:.4f} ")
        print(f"最大RTT: {s.max():.2f} ms")
        print(f"最小RTT: {s.min():.2f} ms")
        print(f"平均RTT: {s.mean():.2f} ms")
        print(f"RTT标准差: {s.std():.2f} ms")

        # 创建包含所有包RTT的数据框
        rtt_data = []
        for pkt_num in range(1, self.total_packets + 1):
            if pkt_num in self.packets and self.packets[pkt_num]['acked']:
                rtt = self.packets[pkt_num]['rtt']
                rtt_data.append({'包号': pkt_num, 'RTT': rtt})
            else:
                rtt_data.append({'包号': pkt_num, 'RTT': None})

        df = pd.DataFrame(rtt_data)
        df.to_csv('rtt_stats.csv', index=False)
        print("\nRTT统计数据已保存到 rtt_stats.csv")
        print(f"已确认包数: {len(confirmed_rtts)}, CSV记录数: {len(rtt_data)}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python udpclient.py  <服务器地址> <端口> [数据包总数] ")
        print("示例: python udpclient.py 127.0.0.1 8888 40")
        sys.exit(1)
    server_ip = sys.argv[1]

    server_port = int(sys.argv[2])
    total_packets = int(sys.argv[3])
    # server_ip = '127.0.0.1'
    # server_port = 6666
    # total_packets = 30
    client = GBNClient(server_ip, server_port, total_packets)
    client.run()