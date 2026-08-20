#!/usr/bin/env python3
import socketserver
import threading

SERVICES = {
    3306: b'5.7.42-log\x00WH838-DB\r\n',
    8888: b'WH838 file-sync service 2.3\r\n',
    9090: b'WH838 message-gateway ready\r\n',
}


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        banner = SERVICES.get(self.server.server_address[1], b'service ready\r\n')
        try:
            self.request.sendall(banner)
        except Exception:
            pass


for port in SERVICES:
    server = socketserver.ThreadingTCPServer(('0.0.0.0', port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

threading.Event().wait()
