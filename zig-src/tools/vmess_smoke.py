#!/usr/bin/env python3
# M7 实机 smoke：VMess over WS（127.0.0.1:19003）+ freedom → 本地 echo 全链。
# 客户端侧密码学为纯 Python 实现（AES-128/GCM/CFB + Go 别名语义 KDF + SHAKE128），
# 启动时以 tests/golden/vmess_aead.txt 黄金向量自校验（KDF/AuthID/密封头/响应头）。
#
# 用法（打包机）：
#   cd /tmp/xrayz-build && $ZIG build            # 先出 zig-out/bin/xrayz
#   python3 tools/vmess_smoke.py

import base64
import hashlib
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import zlib

HOST = '127.0.0.1'
PORT = 19003
WS_PATH = '/vmess'
WS_HOST = 'vmess.smoke.local'
UUID_HEX = 'de53e86485304212a3d7c31e60b62e91'

# ============================ 纯 Python 密码学 ============================

def _gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1)
        b >>= 1
    return r


def _build_sbox():
    exp = [0] * 256
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = _gf_mul(x, 3)
    sbox = [0] * 256
    for b in range(256):
        inv = 0 if b == 0 else exp[(255 - log[b]) % 255]
        s = inv
        for _ in range(4):
            inv = ((inv << 1) | (inv >> 7)) & 0xff
            s ^= inv
        sbox[b] = s ^ 0x63
    return sbox


SBOX = _build_sbox()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def aes128_expand(key):
    assert len(key) == 16
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return w


def aes128_encrypt_block(block, w):
    s = list(block)

    def addrk(rnd):
        for c in range(4):
            for r in range(4):
                s[c * 4 + r] ^= w[rnd * 4 + c][r]

    addrk(0)
    for rnd in range(1, 10):
        s = [SBOX[b] for b in s]
        ns = [0] * 16
        for r in range(4):
            for c in range(4):
                ns[c * 4 + r] = s[((c + r) % 4) * 4 + r]
        s = ns
        for c in range(4):
            a = s[c * 4:c * 4 + 4]
            s[c * 4 + 0] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
            s[c * 4 + 1] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
            s[c * 4 + 2] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
            s[c * 4 + 3] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)
        addrk(rnd)
    s = [SBOX[b] for b in s]
    ns = [0] * 16
    for r in range(4):
        for c in range(4):
            ns[c * 4 + r] = s[((c + r) % 4) * 4 + r]
    s = ns
    addrk(10)
    return bytes(s)


def aes_ecb_encrypt(key, block16):
    assert len(block16) == 16
    return aes128_encrypt_block(block16, aes128_expand(key))

def _gf2_128_mult(x, y):
    r = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            r ^= v
        if v & 1:
            v = (v >> 1) ^ (0xe1 << 120)
        else:
            v >>= 1
    return r


def _ghash(h_int, aad, ct):
    y = 0
    for blob in (aad, ct):
        for i in range(0, len(blob), 16):
            blk = blob[i:i + 16]
            blk = blk + b'\x00' * (16 - len(blk))
            y = _gf2_128_mult(y ^ int.from_bytes(blk, 'big'), h_int)
    lenblk = (len(aad) * 8).to_bytes(8, 'big') + (len(ct) * 8).to_bytes(8, 'big')
    y = _gf2_128_mult(y ^ int.from_bytes(lenblk, 'big'), h_int)
    return y


def _inc32(ctr):
    n = int.from_bytes(ctr[12:], 'big')
    return ctr[:12] + ((n + 1) & 0xffffffff).to_bytes(4, 'big')


def gcm_seal(key, nonce12, pt, aad=b''):
    """返回 (密文, tag)。nonce 12B；计数器起于 nonce||00000002。"""
    w = aes128_expand(key)
    h_int = int.from_bytes(aes128_encrypt_block(b'\x00' * 16, w), 'big')
    ctr = _inc32(nonce12 + b'\x00\x00\x00\x01')
    ct = bytearray()
    for i in range(0, len(pt), 16):
        ks = aes128_encrypt_block(ctr, w)
        blk = pt[i:i + 16]
        ct += bytes(a ^ b for a, b in zip(blk, ks))
        ctr = _inc32(ctr)
    ct = bytes(ct)
    s = _ghash(h_int, aad, ct)
    ej0 = aes128_encrypt_block(nonce12 + b'\x00\x00\x00\x01', w)
    tag = (int.from_bytes(ej0, 'big') ^ s).to_bytes(16, 'big')
    return ct, tag


def gcm_open(key, nonce12, ct, tag, aad=b''):
    w = aes128_expand(key)
    h_int = int.from_bytes(aes128_encrypt_block(b'\x00' * 16, w), 'big')
    s = _ghash(h_int, aad, ct)
    ej0 = aes128_encrypt_block(nonce12 + b'\x00\x00\x00\x01', w)
    expect = (int.from_bytes(ej0, 'big') ^ s).to_bytes(16, 'big')
    if expect != tag:
        raise ValueError('gcm auth failed')
    ctr = _inc32(nonce12 + b'\x00\x00\x00\x01')
    pt = bytearray()
    for i in range(0, len(ct), 16):
        ks = aes128_encrypt_block(ctr, w)
        blk = ct[i:i + 16]
        pt += bytes(a ^ b for a, b in zip(blk, ks))
        ctr = _inc32(ctr)
    return bytes(pt)


def cfb128_decrypt(key, iv, ct):
    """AES-128-CFB（Go cipher.NewCFBDecrypter 语义，整块反馈）。"""
    w = aes128_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        ks = aes128_encrypt_block(prev, w)
        blk = ct[i:i + 16]
        out += bytes(a ^ b for a, b in zip(blk, ks))
        prev = blk
    return bytes(out)


# ---- Go 别名语义 KDF（src/crypto/kdf.zig 的逐行移植；黄金向量锚定）----

class _Sha:
    __slots__ = ('buf',)

    def __init__(self):
        self.buf = b''

    def write(self, d):
        self.buf += d

    def reset_full(self):
        self.buf = b''

    def sum(self):
        return hashlib.sha256(self.buf).digest()


class _Hmac:
    def __init__(self, outer, inner, key):
        self.outer = outer
        self.inner = inner
        eff = key
        if len(key) > 64:
            outer.write(key)
            eff = outer.sum()
        kb = eff + b'\x00' * (64 - len(eff))
        self.ipad = bytes(b ^ 0x36 for b in kb)
        self.opad = bytes(b ^ 0x5c for b in kb)
        inner.write(self.ipad)

    def write(self, d):
        self.inner.write(d)

    def sum(self):
        mid = self.inner.sum()
        self.outer.reset_full()
        self.outer.write(self.opad)
        self.outer.write(mid)
        return self.outer.sum()

    def reset_full(self):
        self.inner.reset_full()
        self.inner.write(self.ipad)


def kdf(key, path):
    s0 = _Sha()
    s1 = _Sha()
    nodes = [_Hmac(s0, s1, b'VMess AEAD KDF')]
    for v in path:
        nodes.append(_Hmac(nodes[-1], nodes[-1], v))
    nodes[-1].write(key)
    return nodes[-1].sum()


def kdf16(key, path):
    return kdf(key, path)[:16]


def fnv1a32(data):
    h = 0x811c9dc5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h


def cmd_key_of(uuid_bytes):
    return hashlib.md5(uuid_bytes + b'c48619fe-8f02-49e0-b9e9-edf763e17e21').digest()

# ---- SHAKE128 尺寸解析器（hashlib.shake_128 的 digest 不增量，需自行缓冲）----

class ShakeSize:
    """SHAKE128(seed) 流式取 2B 大端整数（对应 Zig chacha_key.ShakeSizeParser）。"""

    def __init__(self, seed):
        self.h = hashlib.shake_128(seed)
        self.buf = b''

    def next16(self):
        if len(self.buf) < 2:
            more = self.h.digest(len(self.buf) + 64)
            self.buf = more[len(self.buf):]
        v = int.from_bytes(self.buf[:2], 'big')
        self.buf = self.buf[2:]
        return v

    def next_padding_len(self):
        return self.next16() % 64


# ============================ 黄金向量自校验 ============================
# 向量来源：tests/golden/vmess_aead.txt（打包机 go run tools/gen_golden_vectors.go，
# SELF_CHECK PASSED）。固定输入：t=1700000000, rnd=11223344,
# conn_nonce=0102030405060708, req_iv=11*16, req_key=22*16, resp=0x33, option=0x04

def self_check():
    uuid_b = bytes.fromhex(UUID_HEX)
    ck = cmd_key_of(uuid_b)
    assert ck.hex() == 'd67b69fc215b108c042ab60cf5f01127', 'cmdKey'
    auth_id = bytes.fromhex('95c65bd2aad237b32d36274d0c4aeac5')
    nonce8 = bytes.fromhex('0102030405060708')
    req_iv = b'\x11' * 16
    req_key = b'\x22' * 16

    assert kdf16(ck, [b'AES Auth ID Encryption']).hex() == 'ddc32c8e2a6f59578544787a5130b897', 'kdf authid key'
    assert kdf16(ck, [b'VMess Header AEAD Key_Length', auth_id, nonce8]).hex() == 'aee38794926c11d7607eed4042e8adbf', 'kdf hdr len key'
    assert kdf(ck, [b'VMess Header AEAD Nonce_Length', auth_id, nonce8])[:12].hex() == 'cb33ee08598686e66d58aa21', 'kdf hdr len nonce'
    assert kdf16(ck, [b'VMess Header AEAD Key', auth_id, nonce8]).hex() == 'c85c625e9c45ac391b8d19afd0e1a6de', 'kdf hdr pay key'
    assert kdf(ck, [b'VMess Header AEAD Nonce', auth_id, nonce8])[:12].hex() == 'e88d0d7665311bf1bc955de0', 'kdf hdr pay nonce'

    # AuthID：AES-ECB(t||rnd||crc32)
    pre = (1700000000).to_bytes(8, 'big') + bytes.fromhex('11223344')
    pre += zlib.crc32(pre).to_bytes(4, 'big')
    got = aes_ecb_encrypt(kdf16(ck, [b'AES Auth ID Encryption']), pre)
    assert got == auth_id, 'authid'

    # 密封头（长度段 + 载荷段，AAD=AuthID）
    hp = bytes.fromhex('011111111111111111111111111111111122222222222222222222222222222222330453000101bb020f7777772e6578616d706c652e636f6daaaaaaaaaa7c88411e')
    lk = kdf16(ck, [b'VMess Header AEAD Key_Length', auth_id, nonce8])
    ln = kdf(ck, [b'VMess Header AEAD Nonce_Length', auth_id, nonce8])[:12]
    ct, tag = gcm_seal(lk, ln, len(hp).to_bytes(2, 'big'), auth_id)
    pk = kdf16(ck, [b'VMess Header AEAD Key', auth_id, nonce8])
    pn = kdf(ck, [b'VMess Header AEAD Nonce', auth_id, nonce8])[:12]
    ct2, tag2 = gcm_seal(pk, pn, hp, auth_id)
    sealed = auth_id + ct + tag + nonce8 + ct2 + tag2
    assert sealed.hex() == ('95c65bd2aad237b32d36274d0c4aeac50dc2b3ea13554b0855cd5e1571563e995be5'
                            '0102030405060708a5e57df649bcbde5e6606159b56ffb77248e5be388358b0b3c683609cceb2a2b5abfdf73444e59fac65afce10b26b61f0036fc7979f6fd60568263efebafa91376399b7049cdbc56639c4d9e7da84bfc9b62'), 'sealed header'

    # 响应头 38B 解码：外层 AEAD x2，内层明文 → {0x33, 0x04, 0, 0}
    # （server.go:313-330：内层不加密，CFB 只用于响应体）
    wire = bytes.fromhex('339ef2729742f306dc36165219d7df25d423ada740c6885bdbe4a4f2727090e9ce468e0f624a')
    rk = hashlib.sha256(req_key).digest()[:16]
    ri = hashlib.sha256(req_iv).digest()[:16]
    lpt = gcm_open(kdf16(rk, [b'AEAD Resp Header Len Key']), kdf(ri, [b'AEAD Resp Header Len IV'])[:12], wire[:18][:-16], wire[:18][-16:])
    assert int.from_bytes(lpt, 'big') == 4, 'resp len'
    inner = gcm_open(kdf16(rk, [b'AEAD Resp Header Key']), kdf(ri, [b'AEAD Resp Header IV'])[:12], wire[18:38][:-16], wire[18:38][-16:])
    assert inner == bytes([0x33, 0x04, 0x00, 0x00]), 'resp inner'

    # SHAKE128 NIST 向量（空输入前 16B）+ 顺序 squeeze 语义
    assert hashlib.shake_128(b'').digest(16).hex() == '7f9c2ba4e88f827d616045507605853e', 'shake128 vector'
    ss = ShakeSize(b'')
    assert ss.next16().to_bytes(2, 'big').hex() == '7f9c', 'shake128 squeeze0'
    assert ss.next16().to_bytes(2, 'big').hex() == '2ba4', 'shake128 squeeze1'
    print('crypto self-check vs golden vectors OK')


# ============================ WS 客户端 ============================

def ws_connect(path, host):
    s = socket.create_connection((HOST, PORT), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    req = ('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n'
           'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n' % (path, host, key))
    s.sendall(req.encode())
    buf = b''
    while b'\r\n\r\n' not in buf:
        d = s.recv(4096)
        if not d:
            raise SystemExit('ws handshake failed')
        buf += d
    assert buf.startswith(b'HTTP/1.1 101'), buf
    return s


def ws_send(s, payload):
    """客户端二进制帧（带 mask）。"""
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        hdr = bytes([0x82, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x82, 0x80 | 126]) + n.to_bytes(2, 'big')
    else:
        hdr = bytes([0x82, 0x80 | 127]) + n.to_bytes(8, 'big')
    masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    s.sendall(hdr + mask + masked)


def _recvn(s, n):
    buf = b''
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            return None
        buf += d
    return buf


def ws_recv_frame(s):
    """服务端二进制帧（不带 mask）。返回 (opcode, payload) 或 None。"""
    h = _recvn(s, 2)
    if h is None:
        return None
    assert (h[0] & 0x80) and (h[1] & 0x80) == 0, h  # FIN=1；服务端帧不带 mask
    op = h[0] & 0xF
    n = h[1] & 0x7F
    if n == 126:
        e = _recvn(s, 2)
        if e is None:
            return None
        n = int.from_bytes(e, 'big')
    elif n == 127:
        e = _recvn(s, 8)
        if e is None:
            return None
        n = int.from_bytes(e, 'big')
    pl = _recvn(s, n) if n else b''
    if pl is None:
        return None
    return (op, pl)

# ============================ VMess 客户端 ============================

class VmessClient:
    """VMess AEAD 客户端（请求方向：masking + chunk_stream；响应方向同）。"""

    def __init__(self, sock, cmd_key):
        self.sock = sock
        self.cmd_key = cmd_key
        self.req_iv = os.urandom(16)
        self.req_key = os.urandom(16)
        self.resp_byte = os.urandom(1)[0]
        self.option = 0x01 | 0x04  # RequestOptionChunkStream | RequestOptionChunkMasking
        self.conn_nonce = os.urandom(8)
        self.rnd = os.urandom(4)
        self.wcount = 0
        self.wshake = ShakeSize(self.req_iv)
        self.rcount = 0
        rk = hashlib.sha256(self.req_key).digest()[:16]
        ri = hashlib.sha256(self.req_iv).digest()[:16]
        self.resp_key = rk
        self.resp_iv = ri
        self.rshake = ShakeSize(ri)

    def _wnonce(self):
        n = bytearray(self.req_iv)
        n[0:2] = self.wcount.to_bytes(2, 'big')
        self.wcount = (self.wcount + 1) & 0xffff
        return bytes(n[:12])

    def _rnonce(self):
        n = bytearray(self.resp_iv)
        n[0:2] = self.rcount.to_bytes(2, 'big')
        self.rcount = (self.rcount + 1) & 0xffff
        return bytes(n[:12])

    def send_request(self, dest_port, dest_ip4, payload):
        t = int(time.time())
        pre = t.to_bytes(8, 'big') + self.rnd
        pre += zlib.crc32(pre).to_bytes(4, 'big')
        auth_id = aes_ecb_encrypt(kdf16(self.cmd_key, [b'AES Auth ID Encryption']), pre)
        hp = bytes([1]) + self.req_iv + self.req_key
        hp += bytes([self.resp_byte, self.option, (0 << 4) | 3, 0, 1])
        hp += dest_port.to_bytes(2, 'big') + bytes([1]) + dest_ip4
        hp += fnv1a32(hp).to_bytes(4, 'big')
        lk = kdf16(self.cmd_key, [b'VMess Header AEAD Key_Length', auth_id, self.conn_nonce])
        ln = kdf(self.cmd_key, [b'VMess Header AEAD Nonce_Length', auth_id, self.conn_nonce])[:12]
        ct, tag = gcm_seal(lk, ln, len(hp).to_bytes(2, 'big'), auth_id)
        pk = kdf16(self.cmd_key, [b'VMess Header AEAD Key', auth_id, self.conn_nonce])
        pn = kdf(self.cmd_key, [b'VMess Header AEAD Nonce', auth_id, self.conn_nonce])[:12]
        ct2, tag2 = gcm_seal(pk, pn, hp, auth_id)
        self.auth_id = auth_id  # T3 重放用
        ws_send(self.sock, auth_id + ct + tag + self.conn_nonce + ct2 + tag2)
        self.write_body(payload)
        self.write_body(b'')  # 空终止块（chunk_stream 语义）

    def write_body(self, payload):
        mask = self.wshake.next16()
        size_val = len(payload) + 16
        ct, tag = gcm_seal(self.req_key, self._wnonce(), payload)
        ws_send(self.sock, (mask ^ size_val).to_bytes(2, 'big') + ct + tag)

    def read_response(self, buf):
        """buf: bytearray（已累积的 WS 载荷）。返回回显明文。"""
        while len(buf) < 38:
            fr = ws_recv_frame(self.sock)
            if fr is None:
                raise SystemExit('eof before response header')
            buf += fr[1]
        wire = bytes(buf[:38])
        del buf[:38]
        rk, ri = self.resp_key, self.resp_iv
        lpt = gcm_open(kdf16(rk, [b'AEAD Resp Header Len Key']),
                       kdf(ri, [b'AEAD Resp Header Len IV'])[:12], wire[:18][:-16], wire[:18][-16:])
        assert int.from_bytes(lpt, 'big') == 4, 'resp header len'
        inner = gcm_open(kdf16(rk, [b'AEAD Resp Header Key']),
                       kdf(ri, [b'AEAD Resp Header IV'])[:12], wire[18:38][:-16], wire[18:38][-16:])
        assert inner[0] == self.resp_byte, ('response header byte', inner[0], self.resp_byte)
        assert inner[1] == 0, ('response option must be 0', inner[1])
        out = b''
        while True:
            while len(buf) < 2:
                fr = ws_recv_frame(self.sock)
                if fr is None:
                    return out  # 连接关闭（无终止块时的 EOF）
                buf += fr[1]
            mask = self.rshake.next16()
            size = mask ^ int.from_bytes(buf[:2], 'big')
            del buf[:2]
            if size == 16:
                return out  # 空终止块
            while len(buf) < size:
                fr = ws_recv_frame(self.sock)
                if fr is None:
                    raise SystemExit('eof mid-chunk')
                buf += fr[1]
            blob = bytes(buf[:size])
            del buf[:size]
            out += gcm_open(self.resp_key, self._rnonce(), blob[:-16], blob[-16:])


# ============================ 主流程 ============================

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


def wait_listen(port, timeout=8.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection((HOST, port), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    self_check()
    uuid_b = bytes.fromhex(UUID_HEX)
    cmd_key = cmd_key_of(uuid_b)

    threading.Thread(target=echo_server, daemon=True).start()
    time.sleep(0.3)
    eport = echo_server.port
    print('echo server on', eport)

    xrayz = os.environ.get('XRAYZ_BIN', './zig-out/bin/xrayz')
    cfg = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vmess_smoke.json')
    logf = open('/tmp/vmess_smoke_server.log', 'wb')
    proc = subprocess.Popen([xrayz, 'run', '-c', cfg], stdout=logf, stderr=logf)
    try:
        if not wait_listen(PORT):
            logf.close()
            print(open('/tmp/vmess_smoke_server.log').read())
            raise SystemExit('server did not listen on %d' % PORT)
        print('xrayz listening on', PORT)

        # T1: 全链（WS + VMess AEAD 头 + 分块体 → freedom → echo → 回读）
        s = ws_connect(WS_PATH, WS_HOST)
        c = VmessClient(s, cmd_key)
        c.send_request(eport, bytes([127, 0, 0, 1]), b'hello vmess m7')
        buf = bytearray()
        got = c.read_response(buf)
        assert got == b'hello vmess m7', ('echo mismatch', got)
        print('T1 vmess-over-ws roundtrip OK')
        s.close()

        # T2: 坏 UUID（随机 AuthID）→ 无响应直接关
        s = ws_connect(WS_PATH, WS_HOST)
        ws_send(s, os.urandom(16) + os.urandom(48))
        try:
            r = ws_recv_frame(s)
        except (ConnectionResetError, AssertionError):
            r = None
        assert r is None, ('bad uuid should be closed', r)
        print('T2 bad-uuid closed OK')
        try:
            s.close()
        except Exception:
            pass

        # T3: 重放（T1 的同一 AuthID 在新连接上重放）→ 防重放拒绝
        s = ws_connect(WS_PATH, WS_HOST)
        ws_send(s, c.auth_id + os.urandom(48))
        try:
            r = ws_recv_frame(s)
        except (ConnectionResetError, AssertionError):
            r = None
        assert r is None, ('replay should be closed', r)
        print('T3 replay rejected OK')
        try:
            s.close()
        except Exception:
            pass

        # T4: SIGTERM 优雅退出（exit 0）
        proc.send_signal(signal.SIGTERM)
        t0 = time.time()
        while proc.poll() is None and time.time() - t0 < 6:
            time.sleep(0.1)
        assert proc.poll() == 0, ('exit code', proc.poll())
        print('T4 SIGTERM graceful exit OK')
    finally:
        if proc.poll() is None:
            proc.kill()
        logf.close()

    print('VMESS SMOKE ALL OK')


if __name__ == '__main__':
    main()
