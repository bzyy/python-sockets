import socket
import struct
import select
import logging
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler


logging.basicConfig(level=logging.DEBUG)


class ThreadTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):

    VER = 0x5
    """
    https://www.ietf.org/rfc/rfc1928.txt
    https://rushter.com/blog/python-socks-server/
    
    N_METHODS:
    |0x01| NO AUTHENTICATION REQUIRED|
    |0x01| GSSAPI|
    |0x02| USERNAME/PASSWORD|
    |0x03| to X'7F' IANA ASSIGNED|
    |0x80| to X'FE' RESERVED FOR PRIVATE METHODS|
    |0xFF| NO ACCEPTABLE METHODS|
    
    """
    username = 'username'
    password = 'password'

    def handle(self):
        """客户端与服务端建立TCP连接后，发送的报文格式如下
        |VER|NMETHODS|METHODS  |
        |1  | 1      | 1 to 255|
        NMETHODS: 在METHODS字段中出现的方法的数目；
        METHODS:  客户端支持的认证方式列表，每个方法占1字节。
        """
        socket_version, n_methods = self.connection.recv(2)
        # print(socket_version, n_methods)

        methods = self.get_available_methods(n_methods)
        if 2 not in set(methods):
            return

        """从客户端提供的方法中选择一个最优的方法，或者给出固定的方法
        报文格式如下:
            |VER|METHOD|
            VER: sock版本号: 0x05
            METHOD :服务端选中的方法（若返回0xFF表示没有方法被选中，客户端需要关闭连接;
        """
        self.connection.sendall(struct.pack("!BB", self.VER, 2))

        # 认证
        self.verify_password()

        """认证成功后,发送请求信息的格式.
        报文如下:
            |VER| CMD | RSV |ATYP |DST.ADDR|DST.PORT|
            |1  | 1   |x'00'|  1  |Variable|2       |
        
        RSV: 保留字段
        CMD: 
            |\x01|CONNECT
            |\x02|BIND
            |\x03|UDP
        ATYP:
            |\x01| ipv4
            |\x03| 域名地址
            |\x04| ipv6
        DST.ADDR: 目的地址
        DST.PORT: 目的端口
        """
        version, cmd, _, address_type = struct.unpack("!BBBB",
                                                      self.connection.recv(4))

        if address_type == 1:
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:
            domain_length = ord(self.connection.recv(1)[0])
            address = self.connection.recv(domain_length)
        port = struct.unpack("!H", self.connection.recv(2))[0]

        try:
            """服务器发送答复包的格式
            |VER| REP | RSV |ATYP |BND.ADDR|BND.PORT|
            |1  | 1   |x'00'|  1  |Variable|2       |
            
            VER: socks版本
            REP:
                \x00 succeeded
                \x01 general socks server failure
                \x02 connection not allowed by ruleset
                \x03 Network unreachable
                \x04 Host unreachable
                \x05 Connection refused
                \x06 TTL expired
                \x07 Command not supported
                \x08 Address type not supported
                \x09 to X’FF’ unassigned
            BND.ADDR: 服务器绑定的地址
            BND.PORT: 服务器绑定的端口
            """
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                logging.info('Connected to %s %s' % (address, port))
            else:
                self.server.close_request(self.request)
            _address = struct.unpack("!I",
                                     socket.inet_aton(bind_address[0]))[0]
            _port = bind_address[1]
            reply = struct.pack("!BBBBIH", self.VER, 0, 0, address_type,
                                _address, _port)
        except Exception as err:
            logging.error(err)
        self.connection.sendall(reply)

        # 建立数据交互
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote=remote)

    def get_available_methods(self, n):
        # 读取客户端发送过来的方法列表
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_password(self):
        """验证用户名和密码
        报文格式:
        |0x01|用户名长度(1字节)|用户名|密码长度|密码|
        0x01 -- >验证结果标志
        """
        version = ord(self.connection.recv(1))
        assert version == 1
        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode("utf-8")

        if username == self.username and password == self.password:
            reply = struct.pack("!BB", version, 0)
            self.connection.sendall(reply)
            return True
        reply = struct.pack("!BB", 0xFF)  # --> 0xFF表示认证失败
        self.connection.sendall(reply)
        self.server.close_request(self.request)
        return False

    @staticmethod
    def exchange_loop(client, remote):
        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break


if __name__ == '__main__':
    HOST, PORT = '0.0.0.0', 9011
    server = ThreadTCPServer((HOST, PORT), SocksProxy)
    logging.info("代理地址为:{0}".format(HOST + ":" + str(PORT)))
    server.serve_forever()
