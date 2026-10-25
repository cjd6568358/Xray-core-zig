#!/usr/bin/env python3
# M5 实机 smoke：WS(19001) + VLESS 头 → freedom → 本地 echo → WS 回读；坏 UUID 拒绝
import socket, threading, time, struct

HOST = '127.0.0.1'
PORT = 19001
KEY = 'dGhlIHNhbXBsZSBub25jZQ=='
UUID = bytes.fromhex('de53e86485304212a3d7c31e60b62e91')


def echo_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 0))
    srv.listen(8)
    echo_server.port = srv.getsockname()[1]
    while True:
        c, _ = srv.accept()
        def relay(c=c):
            try:
                while True:
                    d = c.recv(4096)
                    if not d:
                        break
                    c.sendall(d)
            except Exception:
                pass
            finally:
                c.close()
        threading.Thread(target=relay, daemon=True).start()


threading.Thread(target=echo_server, daemon=True).start()
time.sleep(0.3)
EPORT = echo_server.port
print('echo server on', EPORT)


def ws_connect():
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(('GET /free HTTP/1.1\r\nHost: ltetp.tv189.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n'
               'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n' % KEY).encode())
    buf = b''
    while b'\r\n\r\n' not in buf:
        d = s.recv(4096)
        if not d:
            raise SystemExit('handshake failed')
        buf += d
    assert buf.startswith(b'HTTP/1.1 101'), buf
    return s


def ws_send(s, payload):
    mask = b'\x11\x22\x33\x44'
    masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    n = len(payload)
    assert n < 126
    s.sendall(bytes([0x82, 0x80 | n]) + mask + masked)


def ws_recv(s):
    h = b''
    while len(h) < 2:
        d = s.recv(2 - len(h))
        if not d:
            return None
        h += d
    assert (h[0] & 0x80) and (h[1] & 0x80) == 0, h  # FIN=1，服务端帧不带 mask
    n = h[1] & 0x7F
    assert n < 126, h
    pl = b''
    while len(pl) < n:
        d = s.recv(n - len(pl))
        if not d:
            return None
        pl += d
    return (h[0] & 0xF, pl)


# T1: 正常链路（VLESS 头 + 载荷同一 WS 帧 → 预读余量路径）
s = ws_connect()
hdr = bytes([0]) + UUID + bytes([0]) + bytes([1]) + struct.pack('>H', EPORT) + bytes([1]) + bytes([127, 0, 0, 1])
ws_send(s, hdr + b'hello-m5')
data = b''
while data != b'\x00\x00hello-m5':
    r = ws_recv(s)
    assert r is not None, 'connection closed early'
    op, pl = r
    assert op == 2, (op, pl)
    data += pl
    assert len(data) <= 10, data
print('T1 vless-over-ws roundtrip OK')
s.close()

# T2: 坏 UUID → 无响应直接关
s = ws_connect()
bad = bytes([0]) + bytes(range(16)) + bytes([0, 1]) + struct.pack('>H', EPORT) + bytes([1, 127, 0, 0, 1])
ws_send(s, bad)
try:
    r = ws_recv(s)
except ConnectionResetError:
    r = None
assert r is None, r
print('T2 bad-uuid closed OK')
try:
    s.close()
except Exception:
    pass

print('VLESS SMOKE ALL OK')
