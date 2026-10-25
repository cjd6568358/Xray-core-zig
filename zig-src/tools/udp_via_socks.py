#!/usr/bin/env python3
"""经 SOCKS5 UDP ASSOCIATE 做一次真实 UDP 往返（默认 DNS 查询），用于设备侧
XUDP over mux 的端到端验证。

用法：
  python tools/udp_via_socks.py --socks 192.168.1.1:10805 --target 8.8.8.8:53
  python tools/udp_via_socks.py --socks 127.0.0.1:10805 --target 127.0.0.1:29199 --payload hello
"""
import argparse
import os
import random
import socket
import struct
import sys


def dns_query(host='www.baidu.com', qid=None):
    qid = qid if qid is not None else random.randint(1, 65535)
    hdr = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    q = b''.join(bytes([len(p)]) + p.encode() for p in host.split('.')) + b'\x00'
    return qid, hdr + q + struct.pack('!HH', 1, 1)


def parse_hostport(s):
    h, p = s.rsplit(':', 1)
    return h, int(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--socks', default='127.0.0.1:10805')
    ap.add_argument('--target', default='8.8.8.8:53')
    ap.add_argument('--payload', default='')
    ap.add_argument('--tries', type=int, default=3)
    ap.add_argument('--timeout', type=float, default=5.0)
    a = ap.parse_args()

    shost, sport = parse_hostport(a.socks)
    thost, tport = parse_hostport(a.target)

    ctrl = socket.create_connection((shost, sport), a.timeout)
    ctrl.settimeout(a.timeout)
    ctrl.sendall(b'\x05\x01\x00')
    if ctrl.recv(2) != b'\x05\x00':
        print('FAIL socks5 greeting')
        return 1
    ctrl.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    r = ctrl.recv(10)
    if len(r) < 10 or r[1] != 0:
        print('FAIL udp associate: %r' % r)
        return 1
    relay = (socket.inet_ntoa(r[4:8]), struct.unpack('!H', r[8:10])[0])
    print('udp relay = %s:%d' % relay)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(a.timeout)

    if a.payload:
        body = a.payload.encode()
        qid = None
    else:
        qid, body = dns_query()

    hdr = b'\x00\x00\x00\x01' + socket.inet_aton(thost) + struct.pack('!H', tport)
    for i in range(a.tries):
        udp.sendto(hdr + body, relay)
        try:
            data, _ = udp.recvfrom(4096)
        except socket.timeout:
            print('try %d: timeout' % (i + 1))
            continue
        off = 4
        if data[3] == 1:
            off += 4
        elif data[3] == 3:
            off += 1 + data[4]
        elif data[3] == 4:
            off += 16
        off += 2
        payload = data[off:]
        if a.payload:
            ok = payload == body
            print('reply %d bytes, payload %s' % (len(payload), 'MATCH' if ok else 'MISMATCH %r' % payload[:40]))
            return 0 if ok else 1
        if len(payload) < 12:
            print('short reply %r' % payload)
            continue
        rid, flags, qd, an = struct.unpack('!HHHH', payload[:8])
        ok = rid == qid and an > 0
        print('dns reply id=%d ancount=%d -> %s (%d bytes)' % (rid, an, 'OK' if ok else 'BAD', len(payload)))
        return 0 if ok else 1
    print('FAIL no reply')
    return 1


if __name__ == '__main__':
    sys.exit(main())
