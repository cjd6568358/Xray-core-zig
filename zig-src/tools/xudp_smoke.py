#!/usr/bin/env python3
"""XUDP over mux 互通冒烟（Go xray 客户端 <-> Zig 服务端）。

覆盖：
  T1 单包 UDP echo（SOCKS5 UDP ASSOCIATE -> 127.0.0.1:ECHO）
  T2 多包（8 个不同 payload，逐包校验）
  T3 多轮建链（每轮新建 mux 连接 + 新 UDP 会话，验证会话回收）
  T4 客户端 SIGKILL 后服务端线程回落（验证 DownWriter / inflight 无泄漏）

判定标准：T1/T2/T3 全部回包且内容一致；T4 强杀后服务端线程数回落到基线
（±1），进程存活，日志无 panic/segfault/General protection。

用法：python3 tools/xudp_smoke.py [--rounds 5]
"""
import argparse
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = '/tmp/xrayz-build'
XRAYZ = os.path.join(BUILD, 'zig-out/bin/xrayz')
SRV_CFG = os.path.join(BUILD, 'xray.json')
GO_BIN = '/tmp/xray-go-bin'
CLI_CFG = '/tmp/xudp_client.json'
SRV_LOG = '/tmp/xudp_srv.log'
CLI_LOG = '/tmp/xudp_cli.log'

SRV_PORT = 19001
SOCKS_PORT = 10805
ECHO_PORT = 29199
ECHO_IP = '127.0.0.1'


# ---------------------------------------------------------------- echo server
class Echo(threading.Thread):
    daemon = True

    def __init__(self):
        super().__init__()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((ECHO_IP, ECHO_PORT))
        self.stop = False

    def run(self):
        self.s.settimeout(0.5)
        while not self.stop:
            try:
                d, a = self.s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self.s.sendto(d, a)
            except OSError:
                pass


# ------------------------------------------------------------------- helpers
def wait_port(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            c = socket.create_connection(('127.0.0.1', port), 0.3)
            c.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def thread_count(pid):
    try:
        return len(os.listdir('/proc/%d/task' % pid))
    except OSError:
        return -1


def rss_kb(pid):
    try:
        with open('/proc/%d/status' % pid) as f:
            for ln in f:
                if ln.startswith('VmRSS:'):
                    return int(ln.split()[1])
    except OSError:
        pass
    return -1


def socks5_udp():
    """返回 (ctrl_sock, udp_sock, relay_addr)"""
    ctrl = socket.create_connection(('127.0.0.1', SOCKS_PORT), 5)
    ctrl.settimeout(5)
    ctrl.sendall(b'\x05\x01\x00')
    if ctrl.recv(2) != b'\x05\x00':
        raise RuntimeError('socks5 auth failed')
    ctrl.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    r = ctrl.recv(10)
    if len(r) < 10 or r[1] != 0:
        raise RuntimeError('udp associate failed: %r' % r)
    if r[3] == 1:
        relay = (socket.inet_ntoa(r[4:8]), struct.unpack('!H', r[8:10])[0])
    else:
        raise RuntimeError('unexpected atyp %d' % r[3])
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(3)
    return ctrl, udp, relay


def udp_roundtrip(udp, relay, payload, tries=3):
    """经 SOCKS5 UDP 中转发一个包，返回回包 payload 或 None"""
    hdr = b'\x00\x00\x00\x01' + socket.inet_aton(ECHO_IP) + struct.pack('!H', ECHO_PORT)
    for _ in range(tries):
        try:
            udp.sendto(hdr + payload, relay)
            data, _a = udp.recvfrom(4096)
        except socket.timeout:
            continue
        if len(data) < 10:
            continue
        off = 4
        if data[3] == 1:
            off += 4
        elif data[3] == 3:
            off += 1 + data[4]
        elif data[3] == 4:
            off += 16
        else:
            continue
        off += 2
        return data[off:]
    return None


def start_srv():
    log = open(SRV_LOG, 'wb')
    p = subprocess.Popen([XRAYZ, 'run', '-c', SRV_CFG], cwd=BUILD,
                         stdout=log, stderr=subprocess.STDOUT)
    if not wait_port(SRV_PORT):
        raise RuntimeError('server did not listen on %d' % SRV_PORT)
    return p


def start_cli():
    log = open(CLI_LOG, 'wb')
    p = subprocess.Popen([GO_BIN, 'run', '-c', CLI_CFG], cwd='/tmp',
                         stdout=log, stderr=subprocess.STDOUT)
    if not wait_port(SOCKS_PORT):
        raise RuntimeError('client socks did not listen on %d' % SOCKS_PORT)
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rounds', type=int, default=5)
    ap.add_argument('--kill-rounds', type=int, default=3)
    ap.add_argument('--concurrent', type=int, default=6)
    ap.add_argument('--concurrent-rounds', type=int, default=3)
    args = ap.parse_args()

    echo = Echo()
    echo.start()

    srv = start_srv()
    time.sleep(0.5)
    base_threads = thread_count(srv.pid)
    print('server pid=%d baseline_threads=%d' % (srv.pid, base_threads))

    ok = fail = 0
    try:
        # ---- T1/T2：单连接多包 ----
        cli = start_cli()
        ctrl, udp, relay = socks5_udp()
        for i in range(8):
            payload = ('xudp-pkt-%02d-' % i).encode() + bytes([i]) * (i + 1)
            r = udp_roundtrip(udp, relay, payload)
            if r == payload:
                ok += 1
            else:
                fail += 1
                print('  T2 pkt %d MISMATCH got=%r' % (i, r))
        print('T1/T2: %d/%d echo ok (threads=%d)' % (ok, ok + fail, thread_count(srv.pid)))

        # ---- T3：多轮新建 mux 连接 ----
        ctrl.close()
        udp.close()
        cli.send_signal(signal.SIGTERM)
        cli.wait(5)
        time.sleep(1.0)
        print('after client exit: threads=%d' % thread_count(srv.pid))

        t3_ok = t3_n = 0
        for r in range(args.rounds):
            cli = start_cli()
            ctrl, udp, relay = socks5_udp()
            payload = ('round-%d' % r).encode()
            got = udp_roundtrip(udp, relay, payload)
            t3_n += 1
            if got == payload:
                t3_ok += 1
            else:
                print('  T3 round %d FAILED got=%r' % (r, got))
            ctrl.close()
            udp.close()
            cli.send_signal(signal.SIGTERM)
            cli.wait(5)
        time.sleep(1.0)
        print('T3: %d/%d rounds ok (threads=%d)' % (t3_ok, t3_n, thread_count(srv.pid)))

        # ---- T4：客户端 SIGKILL（模拟弱网掉线/进程被杀）后线程回落 ----
        t4_ok = t4_n = 0
        for r in range(args.kill_rounds):
            cli = start_cli()
            ctrl, udp, relay = socks5_udp()
            payload = ('kill-%d' % r).encode()
            _ = udp_roundtrip(udp, relay, payload)  # 建立 XUDP 会话
            cli.send_signal(signal.SIGKILL)          # 不留 FIN，服务端靠 RST/超时
            cli.wait(5)
            # 等 mux 连接被服务端判定结束（读超时 1s 节拍 + 收尾）
            end = time.time() + 15
            settled = -1
            while time.time() < end:
                time.sleep(0.5)
                settled = thread_count(srv.pid)
                if settled <= base_threads + 1:
                    break
            t4_n += 1
            if settled != -1 and settled <= base_threads + 1:
                t4_ok += 1
            else:
                print('  T4 round %d LEAK: threads=%d baseline=%d' % (r, settled, base_threads))
            ctrl.close()
            udp.close()
        print('T4: %d/%d 强杀后线程回落 (threads=%d)' % (t4_ok, t4_n, thread_count(srv.pid)))

        # ---- T5：单条 mux 上并发多 UDP 会话 + 强杀（收尾交错压测）----
        t5_ok = t5_n = 0
        for r in range(args.concurrent_rounds):
            cli = start_cli()
            results = []
            lock = threading.Lock()

            def worker(idx):
                try:
                    c, u, rel = socks5_udp()
                    pay = ('conc-%d-%d' % (r, idx)).encode()
                    got = udp_roundtrip(u, rel, pay)
                    with lock:
                        results.append(got == pay)
                    c.close()
                    u.close()
                except Exception as e:  # noqa: BLE001
                    with lock:
                        results.append(False)
                    print('  T5 worker %d exc: %r' % (idx, e))

            ths = [threading.Thread(target=worker, args=(i,)) for i in range(args.concurrent)]
            for t in ths:
                t.start()
            for t in ths:
                t.join(30)
            t5_n += 1
            if results and all(results):
                t5_ok += 1
            else:
                print('  T5 round %d: %d/%d ok' % (r, sum(1 for x in results if x), len(results)))
            # 强杀客户端（模拟地铁弱网掉线），再等线程回落
            cli.send_signal(signal.SIGKILL)
            cli.wait(5)
            end = time.time() + 20
            settled = -1
            while time.time() < end:
                time.sleep(0.5)
                settled = thread_count(srv.pid)
                if settled <= base_threads + 1:
                    break
            if settled > base_threads + 1:
                print('  T5 round %d 收尾后线程未回落: %d' % (r, settled))
                t5_ok -= 1
        print('T5: %d/%d 并发轮次 ok (threads=%d)' % (t5_ok, t5_n, thread_count(srv.pid)))

        alive = srv.poll() is None
        print('server alive=%s rss_kb=%d' % (alive, rss_kb(srv.pid)))

        total_ok = ok + t3_ok + t4_ok + t5_ok
        total_n = ok + fail + t3_n + t4_n + t5_n
        print('=== RESULT %d/%d ===' % (total_ok, total_n))
        bad = ''
        try:
            with open(SRV_LOG, 'rb') as f:
                bad = f.read().decode('utf-8', 'replace')
        except OSError:
            pass
        for kw in ('panic', 'segmentation', 'General protection', 'SIGSEGV', 'error: '):
            if kw in bad:
                print('!! server log contains %r' % kw)
        return 0 if (total_ok == total_n and alive) else 1
    finally:
        echo.stop = True
        if srv.poll() is None:
            srv.send_signal(signal.SIGTERM)
            try:
                srv.wait(5)
            except subprocess.TimeoutExpired:
                srv.kill()


if __name__ == '__main__':
    sys.exit(main())
