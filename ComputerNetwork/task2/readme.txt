该项目实现了一个 使用UDP协议模拟可靠传输
    实现了tcp的三次握手和四次挥手(这里使用的是标准的四次挥手)

    自定义报文header
    序列号 I (4B)  序列号主要用于确认收到的字节范围
    确认号 I (4B)
    分组号 I (4B)
    标志位 4bit
    校验和 12 bit 两者一共 2 B
    共14B

扩展库:
    Pandas  采用 import pandas as pd 导入

    udpserver.py 和 udpclient.py 采用GBN协议
    运行:
        先启动服务器端 udpserver.py  在命令行输入
            python udpserver.py<端口> [丢包率] [数据损坏率]
            python udpserver.py8888 0.3 0.05
                默认丢包率为0.2 数据损坏率为0.03

        再启动客户端 udpclient.py
            python udpclient.py <服务器地址> <端口> [数据包总数] ")
            python udpclient.py 127.0.0.1 8888 40"






