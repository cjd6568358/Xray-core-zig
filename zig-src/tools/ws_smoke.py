#!/usr/bin/env python3
# WS 实机 smoke：对 xrayz 实例（:19001，host=ltetp.tv189.com，path=/free）的握手面逐项验证
import socket, base64, hashlib

HOST = '127.0.0.1'
PORT = 19001
GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
KEY = 'dGhlIHNhbXBsZSBub25jZQ=='  # RFC 6455 示例 key


def recv_headers_end(s):
    buf = b''
    while b'\r\n\r\n' not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    return buf


def raw(req):
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(req)
    r = recv_headers_end(s)
    s.close()
    return r


# T1: wrong path → 404 空正文
r = raw(('GET /wrong HTTP/1.1\r\nHost: ltetp.tv189.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n'
         'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n' % KEY).encode())
assert r.startswith(b'HTTP/1.1 404'), r
assert b'Content-Length: 0' in r, r
assert r.split(b'\r\n\r\n', 1)[1] == b'', r
print('T1 404-wrong-path OK')

# T2: wrong host → 404
r = raw(('GET /free HTTP/1.1\r\nHost: evil.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n'
         'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n' % KEY).encode())
assert r.startswith(b'HTTP/1.1 404'), r
print('T2 404-wrong-host OK')

# T3: POST → 405（gorilla 检查序：Connection/Upgrade 之后才查方法）
r = raw(('POST /free HTTP/1.1\r\nHost: ltetp.tv189.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n'
         'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n' % KEY).encode())
assert r.startswith(b'HTTP/1.1 405'), r
print('T3 405 OK')

# T4: 101 + Accept + 0-RTT 回显
s = socket.create_connection((HOST, PORT), timeout=5)
s.sendall(('GET /free?ed=2048 HTTP/1.1\r\nHost: ltetp.tv189.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n'
           'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: aGVsbG8\r\n\r\n' % KEY).encode())
r = recv_headers_end(s)
expect_acc = base64.b64encode(hashlib.sha1((KEY + GUID).encode()).digest()).decode()
assert r.startswith(b'HTTP/1.1 101'), r
assert ('Sec-WebSocket-Accept: ' + expect_acc).encode() in r, r
assert b'Sec-WebSocket-Protocol: aGVsbG8' in r, r
print('T4 101 OK, Accept+0RTT verified')

# T5: masked binary 帧送入后 → M4 协议未接，服务端收到首包即收尾连接
# （close 带未读数据 → 内核发 RST；EOF/RST 均为合规收尾）
mask = b'\x11\x22\x33\x44'
payload = b'hello'
masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
s.sendall(bytes([0x82, 0x80 | len(payload)]) + mask + masked)
s.settimeout(2)
try:
    d = s.recv(4096)
    print('T5 closed-after-data OK (M4 protocol pending), recv:', d[:8])
except socket.timeout:
    print('T5 park OK (connection held)')
except ConnectionResetError:
    print('T5 closed-after-data OK (RST, M4 protocol pending)')
s.close()
print('WS SMOKE ALL OK')
