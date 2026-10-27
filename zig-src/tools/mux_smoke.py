#!/usr/bin/env python3
"""Mux 服务端冒烟（纯 python 客户端，不依赖 Go xray）。

覆盖：
  T1 WS + VLESS(cmd=mux) 建通道 → 两个并发 mux 会话各自 echo 回读 → End 帧收尾

用途：
  * 验证 mux 会话级打点（`trace session conn=… sid=…` 行）与父连接汇总（`mux=N`）；
  * 回归 `mux.serve` 的退出顺序（child.finish → mgr.leave → 会话日志）——顺序错了会
    在 aarch64 上 SIGSEGV（sess_arena 先释放，日志块再解引用 job）。

前置：xrayz 以仓库 `xray.json` 起在 127.0.0.1:19001（VLESS+WS，path=/free）。
用法：python3 tools/mux_smoke.py [--host 127.0.0.1] [--port 19001]
"""
import argparse
import socket
import struct
import threading
import time

UUID = bytes.fromhex('de53e86485304212a3d7c31e60b62e91')  # 仓库 xray.json 的测试账号
WS_PATH = '/free'
WS_HOST = 'ltetp.tv189.com'
WS_KEY = 'dGhlIHNhbXBsZSBub25jZQ=='  # RFC 6455 示例 key


def echo_server():
    """本地 echo（mux 会话的出站目标）。"""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(8)
    echo_server.port = srv.getsockname()[1]

    def loop():
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

    threading.Thread(target=loop, daemon=True).start()


def ws_connect(host, port):
    s = socket.create_connection((host, port), timeout=5)
    s.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n'
               'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n' % (WS_PATH, WS_HOST, WS_KEY)).encode())
    buf = b''
    while b'\r\n\r\n' not in buf:
        d = s.recv(4096)
        if not d:
            raise SystemExit('ws handshake failed')
        buf += d
    assert buf.startswith(b'HTTP/1.1 101'), buf
    return s


def ws_send(s, payload):
    mask = b'\x11\x22\x33\x44'
    masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    n = len(payload)
    assert n < 126, n  # 冒烟帧都很小，不实现扩展长度
    s.sendall(bytes([0x82, 0x80 | n]) + mask + masked)


def ws_recv(s):
    h = b''
    while len(h) < 2:
        d = s.recv(2 - len(h))
        if not d:
            return None
        h += d
    assert (h[1] & 0x80) == 0, h  # 服务端帧不带 mask
    n = h[1] & 0x7F
    pl = b''
    while len(pl) < n:
        d = s.recv(n - len(pl))
        if not d:
            return None
        pl += d
    return (h[0] & 0xF, pl)


def mux_new_frame(sid, port, payload):
    """New 帧：[2B metaLen][sid|status=1|opt=1|net=1|port|atype=1|ipv4][2B dataLen][payload]"""
    meta = struct.pack('>H', sid) + bytes([1, 1, 1]) + struct.pack('>H', port) + bytes([1, 127, 0, 0, 1])
    return struct.pack('>H', len(meta)) + meta + struct.pack('>H', len(payload)) + payload


def mux_end_frame(sid):
    """End 帧：meta-only（无 dataLen 段）"""
    meta = struct.pack('>H', sid) + bytes([3, 0])
    return struct.pack('>H', len(meta)) + meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=19001)
    args = ap.parse_args()

    threading.Thread(target=echo_server, daemon=True).start()
    time.sleep(0.3)
    eport = echo_server.port
    print('echo server on', eport)

    s = ws_connect(args.host, args.port)
    ws_send(s, bytes([0]) + UUID + bytes([0]) + bytes([3]))  # VLESS: ver=0, cmd=mux(3)
    r = ws_recv(s)
    assert r is not None and r[1] == b'\x00\x00', r
    print('T0 mux channel up (VLESS response header ok)')

    p1 = b'mux-session-one'
    p2 = b'mux-session-two'
    ws_send(s, mux_new_frame(0x0101, eport, p1))
    ws_send(s, mux_new_frame(0x0202, eport, p2))

    got = b''
    deadline = time.time() + 5
    while (p1 not in got or p2 not in got) and time.time() < deadline:
        r = ws_recv(s)
        if r is None:
            break
        got += r[1]
    assert p1 in got, got
    assert p2 in got, got
    print('T1 two mux sessions roundtrip OK')

    ws_send(s, mux_end_frame(0x0101))
    ws_send(s, mux_end_frame(0x0202))
    time.sleep(0.5)
    s.close()
    time.sleep(0.8)
    print('MUX SMOKE ALL OK')


if __name__ == '__main__':
    main()
