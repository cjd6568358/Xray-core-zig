#!/usr/bin/env python3
# 实机 smoke：UDP 19002 mKCP 会话面（M9 更新：M7 起协议面由 VMess 接管）
# T1 垃圾包 → 静默丢弃（listener.go 0 段语义）
# T2 合法 Data 段 → 建会话 + 回 ACK（cmd=0），且不立即 Terminate
#    （VMess 接管后会话要等 AEAD 头，不再是 M6 占位关闭）
# T3 客户端发 CmdOnly Terminate → 服务端 4s 升级后回 Terminate（cmd=2）
#
# 前置：xrayz 以 xray.json 运行（19002 mkcp 入站）。
import socket, struct, time

HOST = '127.0.0.1'
PORT = 19002
CONV = 0x1234

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)

# T1: 垃圾（非段字节）
s.sendto(b'\xde\xad\xbe\xef\xde\xad', (HOST, PORT))
try:
    d, _ = s.recvfrom(2048)
    print('T1 FAIL: got response to garbage:', d.hex())
    raise SystemExit(1)
except socket.timeout:
    print('T1 garbage discarded OK')

# T2: 合法 Data 段（conv=CONV, number=0, 1 字节载荷）
seg = struct.pack('>HBBIIIH', CONV, 1, 0, 0, 0, 0, 1) + b'x'
s.sendto(seg, (HOST, PORT))

got_ack = False
got_terminate = False
deadline = time.time() + 3
while time.time() < deadline:
    try:
        d, _ = s.recvfrom(2048)
    except socket.timeout:
        continue
    if len(d) < 4:
        continue
    conv, cmd, opt = struct.unpack('>HBB', d[:4])
    if conv != CONV:
        continue
    print('  recv conv=%04x cmd=%d opt=%d len=%d' % (conv, cmd, opt, len(d)))
    if cmd == 0:
        got_ack = True
    if cmd == 2:
        got_terminate = True
assert got_ack, 'T2 FAIL: no ACK for data segment'
assert not got_terminate, 'T2 FAIL: session terminated immediately (VMess should wait for header)'
print('T2 session created + ACK OK (no early Terminate)')

# T3: 新会话 + 16 字节坏 AuthID → VMess 鉴权失败 → 服务端主动关闭
#     → 发送窗空 → terminating → 回 Terminate（cmd=2）
#     （注意：客户端先发 Terminate 时，应用层读到 EOF 直接关连接，不会回 Terminate——
#       与上游 ReadMultiBuffer 的 peer_terminating→EOF 语义一致）
CONV2 = 0x5678
bad = struct.pack('>HBBIIIH', CONV2, 1, 0, 0, 0, 0, 16) + bytes(range(16))
s.sendto(bad, (HOST, PORT))
got_terminate = False
deadline = time.time() + 8
while time.time() < deadline:
    try:
        d, _ = s.recvfrom(2048)
    except socket.timeout:
        continue
    if len(d) < 4:
        continue
    conv, cmd, opt = struct.unpack('>HBB', d[:4])
    if conv == CONV2 and cmd == 2:
        print('  recv conv=%04x cmd=%d opt=%d len=%d' % (conv, cmd, opt, len(d)))
        got_terminate = True
        break
assert got_terminate, 'T3 FAIL: no server-initiated Terminate within 8s'
print('T3 bad AuthID → 服务端主动 Terminate OK')
print('KCP SMOKE ALL OK')
