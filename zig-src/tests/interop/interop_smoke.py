#!/usr/bin/env python3
# M8 实机互通：Go 上游 xray（客户端）↔ Zig xrayz（服务端）端到端。
#
# I1: VLESS+WS  —— Zig 服务端(xray.json 19001) ↔ Go 客户端(socks 10800 → vless/ws)
# I2: VMess+WS  —— Zig 服务端(vmess_smoke.json 19003) ↔ Go 客户端(socks 10801 → vmess/ws)
# I3: 负向      —— Go 客户端坏 UUID → 服务端拒绝 → curl 失败
# I4: VMess+KCP —— Zig 服务端(xray.json 19002) ↔ Go 客户端(socks 10803 → vmess/kcp)
# I5: VLESS+WS+Mux —— Zig 服务端(xray.json 19001) ↔ Go 客户端(socks 10804 → vless/ws + mux)
#                  （xray.json 的生产链路；KCP ARQ + VMess 分块体组合验收）
#
# 用法（打包机）：
#   cd /tmp/xrayz-build && python3 tests/interop/interop_smoke.py
# 环境变量：XRAYZ_BIN（Zig 二进制，默认 ./zig-out/bin/xrayz）
#           XRAY_GO_BIN（Go 二进制，默认 /tmp/xray-go-bin）

import os
import signal
import socket
import subprocess
import sys
import threading
import time
import http.server

HOST = '127.0.0.1'
MARKER = 'INTEROP-OK'

# 大数据面用例（KCP ARQ 验收）：确定性内容，客户端算 sha256 对拍
BIG_LEN = 1024 * 1024
BIG_BODY = bytes((i * 31 + 7) & 0xFF for i in range(BIG_LEN))
BIG_SHA256 = __import__('hashlib').sha256(BIG_BODY).hexdigest()

TOOLS = os.path.dirname(os.path.abspath(__file__))
XRAYZ = os.environ.get('XRAYZ_BIN', './zig-out/bin/xrayz')
XRAY_GO = os.environ.get('XRAY_GO_BIN', '/tmp/xray-go-bin')


def start_http_target():
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/big':
                body = BIG_BODY
            else:
                body = MARKER.encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer((HOST, 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def wait_port(port, timeout=8.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection((HOST, port), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def wait_tcp_closed(port, timeout=8.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection((HOST, port), timeout=0.3)
            s.close()
            time.sleep(0.1)
        except OSError:
            return True
    return False


class Proc:
    def __init__(self, argv, name):
        self.name = name
        self.log = open('/tmp/interop_%s.log' % name, 'wb')
        self.p = subprocess.Popen(argv, stdout=self.log, stderr=self.log)

    def term(self, timeout=6):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            t0 = time.time()
            while self.p.poll() is None and time.time() - t0 < timeout:
                time.sleep(0.1)
            if self.p.poll() is None:
                self.p.kill()
        self.log.close()
        return self.p.poll()


def curl_via_socks(socks_port, url, timeout=15):
    r = subprocess.run(
        ['curl', '-s', '--max-time', str(timeout), '-x', 'socks5h://%s:%d' % (HOST, socks_port), url],
        capture_output=True, text=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def curl_bin_via_socks(socks_port, url, timeout=60):
    r = subprocess.run(
        ['curl', '-s', '--max-time', str(timeout), '-x', 'socks5h://%s:%d' % (HOST, socks_port), url],
        capture_output=True)
    return r.returncode, r.stdout, r.stderr


def main():
    srv_http, target_port = start_http_target()
    print('http target on', target_port)
    url = 'http://%s:%d/' % (HOST, target_port)

    results = []

    # ---- I1: VLESS+WS ----
    zs = Proc([XRAYZ, 'run', '-c', 'xray.json'], 'zig_vless')
    try:
        assert wait_port(19001), 'zig vless server not listening'
        gc = Proc([XRAY_GO, 'run', '-c', os.path.join(TOOLS, 'go_vless_client.json')], 'go_vless_client')
        try:
            assert wait_port(10800), 'go client socks not listening'
            rc, out, err = curl_via_socks(10800, url)
            ok = rc == 0 and out == MARKER
            results.append(('I1 VLESS+WS: Go客户端 → Zig服务端 → HTTP 回靶', ok, 'rc=%d body=%r' % (rc, out)))
        finally:
            rc_go = gc.term()
            results.append(('I1 Go 客户端 SIGTERM exit 0', rc_go == 0, 'rc=%d' % rc_go))
    finally:
        rc_z = zs.term()
        results.append(('I1 Zig 服务端 SIGTERM exit 0', rc_z == 0, 'rc=%d' % rc_z))

    # ---- I2: VMess+WS ----
    zs2 = Proc([XRAYZ, 'run', '-c', os.path.join(TOOLS, '..', '..', 'tools', 'vmess_smoke.json')], 'zig_vmess')
    try:
        assert wait_port(19003), 'zig vmess server not listening'
        gc2 = Proc([XRAY_GO, 'run', '-c', os.path.join(TOOLS, 'go_vmess_client.json')], 'go_vmess_client')
        try:
            assert wait_port(10801), 'go vmess client socks not listening'
            rc, out, err = curl_via_socks(10801, url)
            ok = rc == 0 and out == MARKER
            results.append(('I2 VMess+WS: Go客户端 → Zig服务端 → HTTP 回靶', ok, 'rc=%d body=%r' % (rc, out)))
        finally:
            rc_go = gc2.term()
            results.append(('I2 Go 客户端 SIGTERM exit 0', rc_go == 0, 'rc=%d' % rc_go))
    finally:
        rc_z = zs2.term()
        results.append(('I2 Zig 服务端 SIGTERM exit 0', rc_z == 0, 'rc=%d' % rc_z))

    # ---- I3: 负向（坏 UUID）----
    zs3 = Proc([XRAYZ, 'run', '-c', 'xray.json'], 'zig_vless_neg')
    try:
        assert wait_port(19001), 'zig vless server not listening (neg)'
        gc3 = Proc([XRAY_GO, 'run', '-c', os.path.join(TOOLS, 'go_vless_client_badid.json')], 'go_badid_client')
        try:
            assert wait_port(10802), 'go badid client socks not listening'
            rc, out, err = curl_via_socks(10802, url)
            ok = rc != 0  # 必须失败
            results.append(('I3 坏 UUID：Go 客户端被拒（curl 失败）', ok, 'rc=%d body=%r' % (rc, out)))
        finally:
            rc_go = gc3.term()
    finally:
        zs3.term()

    # ---- I4: VMess+KCP（xray.json 19002 生产链路）----
    zs4 = Proc([XRAYZ, 'run', '-c', 'xray.json'], 'zig_vmess_kcp')
    try:
        assert wait_port(19001), 'zig server not listening (i4)'
        gc4 = Proc([XRAY_GO, 'run', '-c', os.path.join(TOOLS, 'go_vmess_kcp_client.json')], 'go_vmess_kcp_client')
        try:
            assert wait_port(10803), 'go kcp client socks not listening'
            rc, out, err = curl_via_socks(10803, url, timeout=25)
            ok = rc == 0 and out == MARKER
            results.append(('I4 VMess+KCP: Go客户端 → Zig服务端 → HTTP 回靶', ok, 'rc=%d body=%r' % (rc, out)))

            rc2, body, err2 = curl_bin_via_socks(10803, url + 'big', timeout=90)
            import hashlib
            got = hashlib.sha256(body).hexdigest()
            ok2 = rc2 == 0 and len(body) == BIG_LEN and got == BIG_SHA256
            results.append(('I4 VMess+KCP: 1MiB 数据面 sha256 对拍', ok2,
                            'rc=%d len=%d/%d sha=%s' % (rc2, len(body), BIG_LEN, 'ok' if got == BIG_SHA256 else got[:16])))

            # 第二次连接：验证会话表清理 + 新 conv 建会话
            rc3, out3, err3 = curl_via_socks(10803, url, timeout=25)
            ok3 = rc3 == 0 and out3 == MARKER
            results.append(('I4 VMess+KCP: 二次连接（会话回收后新建）', ok3, 'rc=%d body=%r' % (rc3, out3)))
        finally:
            rc_go = gc4.term()
            results.append(('I4 Go 客户端 SIGTERM exit 0', rc_go == 0, 'rc=%d' % rc_go))
    finally:
        rc_z = zs4.term()
        results.append(('I4 Zig 服务端 SIGTERM exit 0', rc_z == 0, 'rc=%d' % rc_z))

    # ---- I5: VLESS+WS + Mux（19001；验证 mux 服务端：客户端 mux 复用单连接）----
    zs5 = Proc([XRAYZ, 'run', '-c', 'xray.json'], 'zig_vless_mux')
    try:
        assert wait_port(19001), 'zig server not listening (i5)'
        gc5 = Proc([XRAY_GO, 'run', '-c', os.path.join(TOOLS, 'go_vless_mux_client.json')], 'go_vless_mux_client')
        try:
            assert wait_port(10804), 'go mux client socks not listening'
            ok_n = 0
            for _ in range(10):
                rc, out, err = curl_via_socks(10804, url, timeout=20)
                if rc == 0 and out == MARKER:
                    ok_n += 1
            results.append(('I5 VLESS+WS+Mux: 10 连全部回靶（mux 会话复用）', ok_n == 10, '%d/10 ok' % ok_n))
        finally:
            rc_go = gc5.term()
            results.append(('I5 Go 客户端 SIGTERM exit 0', rc_go == 0, 'rc=%d' % rc_go))
    finally:
        rc_z = zs5.term()
        results.append(('I5 Zig 服务端 SIGTERM exit 0', rc_z == 0, 'rc=%d' % rc_z))

    srv_http.shutdown()

    print()
    all_ok = True
    for name, ok, detail in results:
        print('%s %s (%s)' % ('PASS' if ok else 'FAIL', name, detail))
        all_ok = all_ok and ok
    print()
    print('INTEROP ALL OK' if all_ok else 'INTEROP FAILED')
    sys.exit(0 if all_ok else 1)


if __name__ == '__main__':
    main()
