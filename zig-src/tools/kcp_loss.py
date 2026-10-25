#!/usr/bin/env python3
# mKCP 丢包韧性回归（§3.5 生产链路验收的补充项）：
# 在 lo 上挂 netem 丢包，跑生产链路 VMess+KCP 的 1MiB 下载 + 多连接小请求，
# 断言 1MiB 数据面 sha256 正确、无卡死，并统计短连接成功率。需要 root（改 qdisc）。
#
# 口径说明（M9 实测 + 上游 A/B）：
#   * 数据完整性：任何成功的传输必须 sha256 一致（失败不掩盖损坏）。
#   * 成功率：mKCP 在丢包下对"短连接/冷启动"有固有缺陷——服务端在应用写完即进入
#     ReadyToClose，尾包丢失后不再重传。A/B 实测（同一 Go 客户端、同一 netem）：
#       5%  丢包 冷启动首个 1MiB：上游 Go 服务端 3/5，Zig 服务端 5/5
#       10% 丢包 10 连小请求：    上游 9/10，Zig 8/10
#     故本脚本按"成功率阈值"判定（1MiB ≥60%、小请求 ≥70%），目的是发现**比上游更差**
#     的回归（例如 M9 修掉的互斥锁死锁会让成功率归零），而不是追求丢包下的 100%。
#
# 用法（打包机）：
#   cd /tmp/xrayz-build
#   $ZIG build                                  # 先出 native zig-out/bin/xrayz
#   python3 tools/kcp_loss.py --loss 5 --rounds 3
#   python3 tools/kcp_loss.py --loss 10 --delay 40 --rounds 2
#
# 退出时一定恢复 qdisc（atexit + finally 双保险）。

import argparse
import atexit
import hashlib
import http.server
import os
import signal
import socket
import subprocess
import sys
import threading
import time

BIG_OK_RATIO = 0.6  # 1MiB 成功率下限（上游同条件冷启动 0.6）
SMALL_OK_RATIO = 0.7  # 短连接成功率下限（上游同条件 0.9，留余量）

HOST = '127.0.0.1'
TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)
XRAYZ = os.environ.get('XRAYZ_BIN', os.path.join(ROOT, 'zig-out/bin/xrayz'))
XRAY_GO = os.environ.get('XRAY_GO_BIN', '/tmp/xray-go-bin')
CLIENT_CFG = os.environ.get('XRAY_GO_CFG', os.path.join(TOOLS, '..', 'tests', 'interop', 'go_vmess_kcp_client.json'))
SERVER_CFG = os.path.join(ROOT, 'xray.json')

BIG_LEN = 1024 * 1024
BIG = bytes((i * 31 + 7) & 0xFF for i in range(BIG_LEN))
BIG_SHA = hashlib.sha256(BIG).hexdigest()


def qdisc_clear():
    subprocess.run(['tc', 'qdisc', 'del', 'dev', 'lo', 'root'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


atexit.register(qdisc_clear)


def qdisc_set(loss_pct, delay_ms=0):
    qdisc_clear()
    if loss_pct <= 0 and delay_ms <= 0:
        return
    cmd = ['tc', 'qdisc', 'add', 'dev', 'lo', 'root', 'netem']
    if loss_pct > 0:
        cmd += ['loss', '%d%%' % loss_pct]
    if delay_ms > 0:
        cmd += ['delay', '%dms' % delay_ms, '10ms', 'distribution', 'normal']
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit('tc failed: %s' % r.stderr.strip())
    print('  netem: loss=%d%% delay=%dms' % (loss_pct, delay_ms))


class HttpTarget:
    def __init__(self):
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = BIG if self.path == '/big' else b'OK'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except Exception:
                    pass

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer((HOST, 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def url(self, path='/'):
        return 'http://%s:%d%s' % (HOST, self.port, path)

    def stop(self):
        self.srv.shutdown()


class Proc:
    def __init__(self, argv, name):
        self.log = open('/tmp/kcp_loss_%s.log' % name, 'wb')
        self.p = subprocess.Popen(argv, stdout=self.log, stderr=self.log)

    def term(self, timeout=8):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            t0 = time.time()
            while self.p.poll() is None and time.time() - t0 < timeout:
                time.sleep(0.1)
            if self.p.poll() is None:
                self.p.kill()
        self.log.close()
        return self.p.poll()


def wait_port(port, timeout=10.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection((HOST, port), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def curl(socks_port, url, timeout):
    t0 = time.time()
    r = subprocess.run(
        ['curl', '-s', '--max-time', str(timeout), '-x', 'socks5h://%s:%d' % (HOST, socks_port), url],
        capture_output=True)
    return r.returncode, r.stdout, time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loss', type=int, default=5, help='丢包率（%）')
    ap.add_argument('--delay', type=int, default=0, help='附加时延（ms）')
    ap.add_argument('--rounds', type=int, default=3, help='1MiB 轮数')
    ap.add_argument('--small', type=int, default=10, help='小请求数')
    ap.add_argument('--timeout', type=int, default=90, help='单请求超时（s）')
    args = ap.parse_args()

    if os.geteuid() != 0:
        print('需要 root 才能改 qdisc（tc netem）')
        return 2

    target = HttpTarget()
    zs = Proc([XRAYZ, 'run', '-c', SERVER_CFG], 'zig')
    gc = None
    results = []
    try:
        assert wait_port(19002, 8) or True  # UDP 无监听可探测，只等服务端起来
        time.sleep(1.0)
        gc = Proc([XRAY_GO, 'run', '-c', CLIENT_CFG], 'go')
        assert wait_port(10803, 10), 'go client socks not listening'

        qdisc_set(args.loss, args.delay)

        big_ok = 0
        for i in range(args.rounds):
            rc, body, el = curl(10803, target.url('/big'), args.timeout)
            ok = rc == 0 and len(body) == BIG_LEN and hashlib.sha256(body).hexdigest() == BIG_SHA
            if ok:
                big_ok += 1
            elif rc == 0 and body:
                # 成功但有数据损坏：单独标红（不是成功率问题）
                results.append(('1MiB #%d 数据损坏' % (i + 1), False, 'len=%d sha 不符' % len(body)))
            print('  %s 1MiB #%d rc=%d len=%d %.2fs' % ('PASS' if ok else 'FAIL', i + 1, rc, len(body), el))

        results.append(('1MiB 成功率（阈值 %.0f%%）' % (BIG_OK_RATIO * 100),
                        big_ok >= args.rounds * BIG_OK_RATIO,
                        '%d/%d ok' % (big_ok, args.rounds)))

        ok_small = 0
        t0 = time.time()
        for i in range(args.small):
            rc, body, el = curl(10803, target.url('/'), 30)
            good = rc == 0 and body == b'OK'
            if good:
                ok_small += 1
            else:
                print('    small #%d FAIL rc=%d el=%.1fs body=%r' % (i + 1, rc, el, body[:16]))
        results.append(('%d 连小请求（阈值 %.0f%%）' % (args.small, SMALL_OK_RATIO * 100),
                        ok_small >= args.small * SMALL_OK_RATIO,
                        '%d/%d ok, %.1fs' % (ok_small, args.small, time.time() - t0)))
        print('  小请求 %d/%d' % (ok_small, args.small))
    finally:
        qdisc_clear()
        if gc:
            rc_go = gc.term()
            results.append(('Go 客户端 SIGTERM exit 0', rc_go == 0, 'rc=%d' % rc_go))
        rc_z = zs.term()
        results.append(('Zig 服务端 SIGTERM exit 0', rc_z == 0, 'rc=%d' % rc_z))
        target.stop()

    print()
    all_ok = True
    for name, ok, detail in results:
        print('%s %s (%s)' % ('PASS' if ok else 'FAIL', name, detail))
        all_ok = all_ok and ok
    print()
    print('KCP LOSS SMOKE %s (loss=%d%% delay=%dms)' % ('ALL OK' if all_ok else 'FAILED', args.loss, args.delay))
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
