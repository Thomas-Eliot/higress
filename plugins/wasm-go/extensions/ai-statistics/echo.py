import os, sys, platform
import http.server as BaseHTTPServer
import socketserver as SocketServer
import threading
import urllib.request as urllib2
import urllib.parse as urllib
import http.client as httplib
import shutil
import re
import time
import json
try:
    from io import StringIO, BytesIO
except ImportError:
    from StringIO import StringIO
    from io import BytesIO

########################################################################################################
#   Overload and Impl the HttpRequest Handler.
########################################################################################################
class SimpleHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    
    def read_chunked_body(self):
        """读取分块传输编码的请求体"""
        body = b''
        while True:
            # 读取分块大小行
            line = self.rfile.readline()
            if not line:
                break
            
            # 解析分块大小（十六进制）
            line = line.decode('utf-8').strip()
            if not line:
                continue
            
            try:
                chunk_size = int(line.split(';')[0], 16)
            except ValueError:
                break
            
            if chunk_size == 0:
                # 读取最后的 CRLF
                self.rfile.readline()
                break
            
            # 读取分块数据
            chunk = self.rfile.read(chunk_size)
            body += chunk
            
            # 读取分块后的 CRLF
            self.rfile.readline()
        
        return body
    
    def get_request_body(self):
        """获取请求体，支持普通和分块传输"""
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            return self.read_chunked_body()
        else:
            content_length = int(self.headers.get('Content-Length', 0))
            return self.rfile.read(content_length) if content_length > 0 else b''
    
    #[GET]
    def do_GET(self):
        self.do_POST()

    def do_POST(self):
        # 读取请求体
        body_bytes = self.get_request_body()
        body = body_bytes.decode('utf-8') if body_bytes else ''
        
        # Parse the headers
        headers = {key: self.headers[key] for key in self.headers.keys()}
        
        # Construct the response object
        response = {
            'server_port': self.server.server_port,
            'header': headers,
            'body': body
        }
       # time.sleep(3)
        response_json = json.dumps(response, ensure_ascii=False)
        response_bytes = response_json.encode('utf-8')
    
    # Send the response back to the client
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_bytes)))  # ✅ 使用字节长度
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_PUT(self):
        # 读取请求体
        body_bytes = self.get_request_body()
        body = body_bytes.decode('utf-8') if body_bytes else ''
        
        parsed_path = urllib.urlparse(self.path)
        conn = httplib.HTTPConnection(parsed_path.netloc)
        headers = {"Host": "status.taobao.com"}
        conn.request("GET", "/cag-gateway-aliyun-com/check_health", None, headers)
        r = conn.getresponse()
        data = r.read()
        
        # 构建响应对象，包含body
        response = {
            'server_port': self.server.server_port,
            'header': {key: self.headers[key] for key in self.headers.keys()},
            'body': body,
            'response_data': data.decode('utf-8')
        }
        
        response_json = json.dumps(response, ensure_ascii=False).encode('utf-8')
        
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", str(len(response_json)))
        self.end_headers()
        self.wfile.write(response_json)

########################################################################################################
#   Main Function
########################################################################################################
class ThreadingServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    pass

if __name__ == '__main__':
    serveraddr = ('', int(sys.argv[1]))
    srvr = ThreadingServer(serveraddr, SimpleHTTPRequestHandler)
    srvr.serve_forever()
