# coding = utf-8
import sys
import time
import datetime
import os
import socket
import struct

default_server = "10.3.9.6"  # 默认外部服务器地址
local_address = socket.gethostbyname(socket.gethostname())  # 本地地址
port = 53  # 端口号
default_file = "dnsrelay.txt"  # 读取映射表的默认文件名
debug1 = "-d"  # 调试等级1
debug2 = "-dd"  # 调试等级2
debug_level = 0  # 调试等级
buf_size = 512  # 传输缓冲区大小
domain_ip = {}  # 创建字典domain_ip，用于存储映射表
trans = {}  # 创建字典trans，用于存储ID转换表
real_server = default_server  # 实际外部服务器地址
real_file = default_file  # 读取映射表的实际文件名
default_TTL = 176800  # 生存时间，稳定资源记录为2天
shield_IP = "0.0.0.0"  # 屏蔽的IP地址
Order = 1  # 调试等级debug_level为1时序列号


# 定义DNS报文头类
class DNSPackage:
    # 查询报解析
    def QueryAnalysis(self, arr):
        # ID
        self.ID = (arr[0] << 8) + arr[1]
        # FLAGS
        self.QR = arr[2] >> 7
        self.Opcode = (arr[2] % 128) >> 3
        self.AA = (arr[2] % 8) >> 2
        self.TC = (arr[2] % 4) >> 1
        self.RD = arr[2] % 2
        self.RA = arr[3] >> 7
        self.Z = (arr[3] % 128) >> 4
        self.RCODE = arr[3] % 16
        # 资源记录数量
        self.QDCOUNT = (arr[4] << 8) + arr[5]
        self.ANCOUNT = (arr[6] << 8) + arr[7]
        self.NSCOUNT = (arr[8] << 8) + arr[9]
        self.ARCOUNT = (arr[10] << 8) + arr[11]
        # 查询部分内容
        name_length = 0
        self.name = ""
        flag = 12
        while arr[flag] != 0x0:
            for i in range(flag + 1, flag + arr[flag] + 1):
                self.name = self.name + chr(arr[i])
            name_length = name_length + arr[flag] + 1
            flag = flag + arr[flag] + 1
            if arr[flag] != 0x0:
                self.name = self.name + "."
        name_length = name_length + 1
        self.name.casefold()
        flag = flag + 1
        self.qtype = (arr[flag] << 8) + arr[flag + 1]
        self.qclass = (arr[flag + 2] << 8) + arr[flag + 3]
        #返回值为查询域名长度，用于确定响应包字节数组长度
        return name_length
    def output(self):
        print("ID " + str(hex(self.ID)) + ",",end = ' ')
        print("QR " + str(self.QR) + ",", end=' ')
        print("Opcode " + str(self.Opcode) + ",", end=' ')
        print("AA " + str(self.AA) + ",", end=' ')
        print("TC " + str(self.TC) + ",", end=' ')
        print("RD " + str(self.RD) + ",", end=' ')
        print("RA " + str(self.RA) + ",", end=' ')
        print("Z " + str(self.Z) + ",", end=' ')
        print("RCODE " + str(self.RCODE) + ",", end=' ')
        print("QDCOUNT " + str(self.QDCOUNT) + ",", end=' ')
        print("ANCOUNT " + str(self.ANCOUNT) + ",", end=' ')
        print("NSCOUNT " + str(self.NSCOUNT) + ",", end=' ')
        print("ARCOUNT " + str(self.ARCOUNT))

class IDsource:
    def getSrc(self,IP,Port,idsrc):
        self.addr = (IP,Port)
        self.IDsrc = idsrc

# getTable函数用于从指定文件读取映射表
def getTable(fileName, domain_ip):
    f = open(fileName)
    # 将映射表插入
    for each_line in f:
        flag = each_line.find(" ")
        ip = each_line[:flag]
        domain = each_line[(flag + 1):(len(each_line) - 1)].casefold()
        domain_ip[domain] = ip


# 输出系统时间及调试命令用法
print("DNSRELAY, Version 1.0, Build: " + time.strftime("%b %d %Y %H:%M:%S", time.localtime(time.time())))
print("Usage: dnsrelay [-d | -dd] [<dns-server>] [db-file]\n")

# 解析调试命令中的信息
if len(sys.argv) == 2:
    if sys.argv[1] == debug1:
        debug_level = 1
    elif sys.argv[1] == debug2:
        debug_level = 2
    else:
        try:
            # 将输入字符串转化为点分十进制IP地址
            flag = struct.unpack('i', socket.inet_aton(sys.argv[1]))[0]
            real_server = socket.inet_ntoa(struct.pack('i', socket.htonl(socket.ntohl(flag))))
        except OSError:
            print('Bad name server IP address "' + sys.argv[1] + '".')
            sys.exit(0)

elif len(sys.argv) == 3:
    if sys.argv[1] == debug1 or sys.argv[1] == debug2:
        if sys.argv[1] == debug1:
            debug_level = 1
        elif sys.argv[1] == debug2:
            debug_level = 2
        try:
            flag = struct.unpack('i', socket.inet_aton(sys.argv[2]))[0]
            real_server = socket.inet_ntoa(struct.pack('i', socket.htonl(socket.ntohl(flag))))
        except OSError:
            print('Bad name server IP address "' + sys.argv[2] + '".')
            sys.exit(0)
    else:
        real_file = sys.argv[2]
        try:
            flag = struct.unpack('i', socket.inet_aton(sys.argv[1]))[0]
            real_server = socket.inet_ntoa(struct.pack('i', socket.htonl(socket.ntohl(flag))))
        except OSError:
            print('Bad name server IP address "' + sys.argv[1] + '".')
            sys.exit(0)

elif len(sys.argv) >= 4:
    if sys.argv[1] == debug1:
        debug_level = 1
    elif sys.argv[1] == debug2:
        debug_level = 2
    real_file = sys.argv[3]
    try:
        flag = struct.unpack('i', socket.inet_aton(sys.argv[2]))[0]
        real_server = socket.inet_ntoa(struct.pack('i', socket.htonl(socket.ntohl(flag))))
    except OSError:
        print('Bad name server IP address "' + sys.argv[2] + '".')
        sys.exit(0)

# 输出调试准备信息
print("Name server " + real_server + ":" + str(port) + ".")
print("Debug level " + str(debug_level) + ".")

# 创建服务器套接字并绑定本地地址
udpServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udpServer.bind((local_address,port))
print("Bind UDP port " + str(port) + " ...OK!")

# 从文件中读取映射表
try:
    getTable(real_file, domain_ip)
    print('Try to load table "' + real_file + '" ... OK')
    if debug_level == 2:
        order = 1
        for key in domain_ip:
            print("          " + str(order) + ":" + domain_ip[key] + "\t" + key)
            order = order + 1
    print(str(domain_ip.__len__()) + " names, occupy " + str(os.path.getsize(real_file)) + " bytes memory")
except OSError:
    print('Try to load table "' + real_file + '" ... Ignored')
    print("0 names, occupy 1 bytes memory")

starttime = datetime.datetime.now()

# 收发包部分，核心
while True:
    # 接受DNS包并解析
    data, addr = udpServer.recvfrom(buf_size)
    getMsg = bytearray(data)
    RecvDp = DNSPackage()
    name_length = RecvDp.QueryAnalysis(getMsg)
    # 若为查询报
    if RecvDp.QR == 0 and RecvDp.qtype == 1:
        if debug_level == 1:
            endtime = datetime.datetime.now()
            interval = (endtime - starttime).seconds
            print("          " + str(interval) + ":" + str(Order) + "\t" + RecvDp.name)
            Order = Order + 1
        if debug_level == 2:
            print("RECV from " + addr[0] + ":" + str(addr[1]) + " (" + str(getMsg.__len__()) + " bytes)  ", end='')
            for each in getMsg:
                print(hex(each), end=' ')
            print('')
            RecvDp.output()
        # 若在本机映射表可找到域名对应IP地址
        if domain_ip.get(RecvDp.name) != None:
            # 若IP地址不为"0.0.0.0"，则按DNS报文规则创建字符数组，将查询结果写入数组并发回客户端
            if domain_ip.get(RecvDp.name) != shield_IP:
                res = bytearray(32 + name_length)
                res[0] = RecvDp.ID >> 8
                res[1] = RecvDp.ID % 256
                res[2] = 0x81
                res[3] = 0x80
                res[4] = 0x0
                res[5] = 0x1
                res[6] = 0x0
                res[7] = 0x1
                res[8] = 0x0
                res[9] = 0x0
                res[10] = 0x0
                res[11] = 0x0
                for i in range(12, 16 + name_length):
                    res[i] = getMsg[i]
                flag = name_length + 16
                res[flag] = 0xc0
                res[flag + 1] = 0x0c
                res[flag + 2] = 0x0
                res[flag + 3] = 0x1
                res[flag + 4] = 0x0
                res[flag + 5] = 0x1
                res[flag + 6] = default_TTL >> 24
                res[flag + 7] = (default_TTL >> 16) % 256
                res[flag + 8] = (default_TTL >> 8) % 256
                res[flag + 9] = default_TTL % 256
                res[flag + 10] = 0x0
                res[flag + 11] = 0x4
                getIP = domain_ip.get(RecvDp.name)
                IPtuple = getIP.split(sep='.')
                res[flag + 12] = int(IPtuple[0])
                res[flag + 13] = int(IPtuple[1])
                res[flag + 14] = int(IPtuple[2])
                res[flag + 15] = int(IPtuple[3])
                udpServer.sendto(bytes(res),addr)
                if debug_level == 2:
                    SendDp = DNSPackage()
                    SendDp.QueryAnalysis(res)
                    print("SEND to " + addr[0] + ":" + str(addr[1]) + " (" + str(res.__len__()) + " bytes)  ",end = '')
                    for each in res:
                        print(hex(each),end = ' ')
                    print('')
                    SendDp.output()
            # 若IP地址为"0.0.0.0"，则按DNS报文规则创建字符数组，返回差错信息并发回客户端
            else:
                res = bytearray(16 + name_length)
                res[0] = RecvDp.ID >> 8
                res[1] = RecvDp.ID % 256
                res[2] = 0x81
                res[3] = 0x83
                res[4] = 0x0
                res[5] = 0x1
                res[6] = 0x0
                res[7] = 0x0
                res[8] = 0x0
                res[9] = 0x0
                res[10] = 0x0
                res[11] = 0x0
                for i in range(12, 16 + name_length):
                    res[i] = getMsg[i]
                udpServer.sendto(bytes(res), addr)
        #若找不到查询结果，将请求外部服务器查询
        else:
            endtime = datetime.datetime.now()
            interval = (endtime - starttime).seconds
            # 每2秒刷新一次ID转换表
            if interval % 2 == 0:
                trans = {}
            # 若ID转换表长度小于最大尺寸则将转换信息存入转换表，并将查询请求转发给外部服务器
            if trans.keys().__len__() < 0xffff:
                idsrc = IDsource()
                idsrc.getSrc(addr[0],addr[1],RecvDp.ID)
                iddst = trans.keys().__len__()
                trans[iddst] = idsrc
                getMsg[0] = iddst >> 8
                getMsg[1] = iddst % 256
                udpServer.sendto(bytes(getMsg),(real_server,port))
                if debug_level == 2:
                    print("SEND to " + real_server + ":" + str(port) + " (" + str(getMsg.__len__()) + " bytes) ",end='')
                    print("[ID:" + str(hex(RecvDp.ID)) + "->" + str(hex(iddst)) + "]")

    # 若为响应报，即来自外部服务器
    if RecvDp.QR == 1:
        idSRC = trans.get(RecvDp.ID)
        getMsg[0] = idSRC.IDsrc >> 8
        getMsg[1] = idSRC.IDsrc % 256
        if debug_level == 2:
            print("RECV from " + addr[0] + ":" + str(addr[1]) + " (" + str(getMsg.__len__()) + " bytes)  ", end='')
            for each in getMsg:
                print(hex(each), end=' ')
            print('')
            RecvDp.output()
        udpServer.sendto(bytes(getMsg), idSRC.addr)
        if debug_level == 2:
            print("SEND to " + idSRC.addr[0] + ":" + str(idSRC.addr[1]) + " (" + str(getMsg.__len__()) + " bytes) ", end='')
            print("[ID:" + str(hex(RecvDp.ID)) + "->" + str(hex(idSRC.IDsrc)) + "]")

# 关闭服务器，释放套接字
udpServer.close()
