#!/usr/bin/env python3
import socket
import threading

LISTEN = ('0.0.0.0', 8080)
TARGET = ('172.30.2.2', 8080)


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except Exception:
        pass


def handle(client):
    try:
        target = socket.create_connection(TARGET, timeout=5)
    except Exception:
        client.close()
        return
    threading.Thread(target=pump, args=(client, target), daemon=True).start()
    threading.Thread(target=pump, args=(target, client), daemon=True).start()


sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(LISTEN)
sock.listen(64)
while True:
    client, _ = sock.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
