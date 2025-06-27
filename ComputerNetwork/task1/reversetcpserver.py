import socket
import struct
import threading


def create_server_socket(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"服务端已启动! ip地址: {host} 端口号:{port}")
    print(f"正在等待客户端连接......")

    client_count = 0
    while True:
        client_count += 1
        conn, address = server_socket.accept()
        print(f"服务器已接受到客户端{client_count}号的连接请求,客户端信息{address}")
        thread = threading.Thread(target=client_handler, args=(conn, address, client_count))
        thread.start()


def client_handler(conn, address, num):
    try:
        # 接收初始化报文
        initialization_data = b''
        while len(initialization_data) < 6:
            chunk = conn.recv(6 - len(initialization_data))
            if not chunk:
                print(f"客户端{num}连接断开!")
                return
            initialization_data += chunk

        # 解析初始化报文
        try:
            packet_type, n_reverse_chunks = struct.unpack('>HI', initialization_data)
        except struct.error:
            print(f"客户端{num}发送的初始化报文格式错误")
            return

        if packet_type != 1:
            print(f"无效的报文类型! 期望1, 实际收到{packet_type}")
            return

        if n_reverse_chunks <= 0:
            print("要做reverse的块数必须是正整数!")
            return

        # 发送同意报文
        conn.sendall(struct.pack('>H', 2))

        for i in range(n_reverse_chunks):
            # 读取请求头
            request_header = b""
            while len(request_header) < 6:
                req_header_chunk = conn.recv(6 - len(request_header))
                if not req_header_chunk:
                    print(f"客户端{num}在发送reverseRequest报文时断开连接!")
                    return
                request_header += req_header_chunk

            # 解析请求头
            try:
                packet_type, len_data = struct.unpack('>HI', request_header)
            except struct.error:
                print(f"客户端{num}发送的请求头格式错误")
                return

            if packet_type != 3:
                print(f"无效的报文类型! 期望3, 实际收到{packet_type}")
                return

            # 接收数据
            data = b""
            while len(data) < len_data:
                data_chunk = conn.recv(min(4096, len_data - len(data)))  # 添加缓冲区大小限制
                if not data_chunk:  # 关键修复：使用正确的变量名 data_chunk
                    print(f"客户端{num}在发送reverse数据时断开连接!")
                    return
                data += data_chunk

            # 反转数据并发送响应
            reversed_data = data[::-1]
            answer_header = struct.pack('>HI', 4, len(reversed_data))
            conn.sendall(answer_header + reversed_data)

    except Exception as e:
        print(f"处理客户端{num}时发生错误: {e}")
    finally:
        conn.close()
        print(f"客户端{num}断开连接!")


if __name__ == '__main__':
    server_host = "127.0.0.1"
    server_port = 6666
    create_server_socket(server_host, server_port)