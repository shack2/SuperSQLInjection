"""eval 钩子测试用迷你回显服务：/echo-ua 返回 User-Agent 头内容"""
import http.server
import sys

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (self.headers.get("User-Agent") or "").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

http.server.HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8199), H).serve_forever()
