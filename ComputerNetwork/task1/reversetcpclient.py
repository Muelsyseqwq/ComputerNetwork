import socket
import struct
import random
import sys


def input_check():
    if len(sys.argv) != 6:
        print(
            "请正确输入参数: python reversetcpclient.py <server_address> <server_port> <data_file_path> <Lmin> <Lmax>")
        sys.exit(1)

    server_address = sys.argv[1]
    server_port = int(sys.argv[2])
    data_file_path = sys.argv[3]
    Lmin = int(sys.argv[4])
    Lmax = int(sys.argv[5])
    if Lmin <= 0 or Lmax <= 0 or Lmin > Lmax:
        print("请输入合法的Lmin和Lmax!")
        sys.exit(1)  # 修正：错误时应退出程序
    return server_address, server_port, data_file_path, Lmin, Lmax


def get_data_from_file(file_path):
    '''获取文件的数据'''
    try:

        with open(file_path, 'rb') as f:
            file_data = f.read()
    except Exception as e:
        print(f"读取文件错误: {e}")
        sys.exit(1)
    if not file_data:
        print("错误：输入文件为空")
        sys.exit(1)
    return file_data


def spilt_chunks(data, Lmin, Lmax):
    '''随机分割数据'''
    data_chunks = []
    total_len = len(data)
    current = 0
    while current < total_len:
        remaining = total_len - current  # 修正：变量名拼写错误

        if remaining < Lmin:
            chunk_size = remaining
        else:
            chunk_size = random.randint(Lmin, min(Lmax, remaining))

        data_chunks.append(data[current: current + chunk_size])
        current += chunk_size

    return data_chunks


def create_client():
    try:
        server_host, server_port, data_file_path, Lmin, Lmax = input_check()  # 读入cmd数据

        # 建立连接
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_client.connect((server_host, server_port))

        data = get_data_from_file(data_file_path)  # 获取数据
        chunks = spilt_chunks(data, Lmin, Lmax)  # 分割数据
        if len(chunks) <= 0:
            print("数据包分割出错!请输入正确的Lmin,Lmax!")
            return
        n_reverse_chunks = len(chunks)

        # 发送初始化报文1
        initialization_packet = struct.pack('>HI', 1, n_reverse_chunks)
        socket_client.sendall(initialization_packet)

        agree_packet = b""
        while len(agree_packet) < 2:  # 确保读入两个字节
            agree_chunk = socket_client.recv(2 - len(agree_packet))
            if not agree_chunk:
                print("错误：在接收agree报文时与服务器断开连接!")
                return
            agree_packet += agree_chunk

        packet_type, = struct.unpack('>H', agree_packet)
        if packet_type != 2:
            print(f"无效的报文类型!")
            print(f"期望收到报文类型2.")
            print(f"接收到报文类型{packet_type}.")
            return

        reversed_chunks = []
        for i, chunk in enumerate(chunks):
            request_header = struct.pack('>HI', 3, len(chunk))
            socket_client.sendall(request_header + chunk)  # 发送数据包

            answer_header = b''
            while len(answer_header) < 6:
                answer_chunk = socket_client.recv(6 - len(answer_header))
                if not answer_chunk:
                    print("错误：在接收answer报文时与服务器断开连接!")
                    return
                answer_header += answer_chunk

            answer_type, answer_length = struct.unpack('>HI', answer_header)
            if answer_type != 4:
                print(f"无效的报文类型!")
                print(f"期望收到报文类型4.")
                print(f"接收到报文类型{answer_type}.")  # 修正：使用answer_type变量
                return

            reversed_data = b''
            while len(reversed_data) < answer_length:
                reversed_chunk = socket_client.recv(answer_length - len(reversed_data))
                if not reversed_chunk:
                    print("错误：与服务器在接收反转数据时断开连接!")
                    return
                reversed_data += reversed_chunk

            # 输出反转结果
            try:
                text = reversed_data.decode('ascii')
            except UnicodeDecodeError:
                text = str(reversed_data)
            print(f"{i + 1}: {text}")
            reversed_chunks.insert(0, reversed_data)  # 将反转块插入列表开头

        # 保存完整反转文件 (移到循环外部)
        output_file = 'output.txt'
        with open(output_file, 'wb') as f:
            for chunk in reversed_chunks:
                f.write(chunk)
        print(f"文件已成功保存在:{output_file}")

    except Exception as e:
        print(f"客户端发生错误: {e}")
    finally:
        socket_client.close()  # 确保关闭socket连接


def main():
    create_client()


if __name__ == '__main__':
    main()