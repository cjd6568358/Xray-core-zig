#!/usr/bin/env python3
# 弱网韧性回归（WS 生产链路，模拟地铁/移动网络）：
#   在 lo 上挂 tc netem（丢包 + 延迟 + 抖动 + 乱序），跑
#     curl → Go 客户端(WS, mux 可选) → 服务端 19001 → freedom → HTTP 靶
#   统计成功率与延迟分位数，并对成功传输做 sha256 校验。
#
# 为什么单独做这一项（M21 教训）：
#   kcp_loss.py 只覆盖 19002 的 mKCP；而手机默认走 19001 的 VLESS+WS。
#   2026-10-23 地铁时段线上体感"丢包严重"，日志显示真因是 mux 不支持导致客户端
#   回退直连 + 64 并发上限拒绝 7244 次——不是链路丢包。本工具用于：
#     ① 量化 WS 链路在弱网下的真实成功率/延迟（区分"链路差"与"我们挡掉"）
#     ② 与 Go 服务端 A/B（同客户端、同 netem），发现"比上游更差"的回归
#     ③ 观察服务端日志里 connection closed 的 duration 分布（短命连接 = 重连风暴）
#
# 用法（打包机，需 root 改 qdisc）：
#   cd /tmp/xrayz-build
#   $ZIG build
#   python3 tools/ws_weaknet.py --server zig --loss 0  --rounds 10
#   python3 tools/ws_weaknet.py --server zig --loss 5 --delay 100 --jitter 20 --rounds 10
#   python3 tools/ws_weaknet.py --server go  --loss 5 --delay 100 --jitter 20 --rounds 10
#   python3 tools/ws_weaknet.py --server zig --loss 10 --reorder 5 --rounds 8 --big
#
# 退出时一定恢复 qdisc（atexit + finally 双保险）。

import argparse
import atexit
import hashlib
import http.server
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

HOST = '127.0.0.1'
TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)
XRAYZ = os.environ.get('XRAYZ_BIN', os.path.join(ROOT, 'zig-out/bin/xrayz'))
XRAY_GO = os.environ.get('XRAY_GO_BIN', '/tmp/xray-go-bin')
SERVER_CFG = os.path.join(ROOT, 'xray.json')
UUID = 'de53e864-8530-4212-a3d7-c31e60b62e91'
WS_PATH = '/free'
WS_HOST = 'ltetp.tv189.com'
SOCKS_PORT = 10807
SRV_PORT = 19001

BIG_LEN = 1024 * 1024
BIG = bytes((i * 31 + 7) & 0xFF for i in range(BIG_LEN))
BIG_SHA = hashlib.sha256(BIG).hexdigest()

# 成功率门限（M21 基线：0% 必须 100%；弱网按 ≥80% 判定，只抓"比上游更差"）
OK_RATIO_WEAK = 0.8


def qdisc_clear():
    subprocess.run(['tc', 'qdisc', 'del', 'dev', 'lo', 'root'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


atexit.register(qdisc_clear)


def qdisc_set(loss_pct, delay_ms, jitter_ms, reorder_pct):
    qdisc_clear()
    if not (loss_pct or delay_ms or jitter_ms or reorder_pct):
        return
    cmd = ['tc', 'qdisc', 'add', 'dev', 'lo', 'root', 'netem']
    if delay_ms:
        cmd += ['delay', '%dms' % delay_ms]
        if jitter_ms:
            cmd += ['%dms' % jitter_ms, 'distribution', 'normal']
    if loss_pct:
        cmd += ['loss', '%d%%' % loss_pct]
    if reorder_pct:
        cmd += ['reorder', '%d%%' % reorder_pct, '50%']
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    print('  netem: loss=%d%% delay=%dms jitter=%dms reorder=%d%%'
          % (loss_pct, delay_ms, jitter_ms, reorder_pct))


def start_http_target():
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = BIG if self.path == '/big' else b'WS-WEAKNET-OK'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer((HOST, 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def gen_client_cfg(path, with_mux):
    cfg = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{'tag': 'socks-in', 'listen': HOST, 'port': SOCKS_PORT,
                      'protocol': 'socks', 'settings': {'udp': False}}],
        'outbounds': [{
            'tag': 'vless-ws', 'protocol': 'vless',
            'settings': {'vnext': [{'address': HOST, 'port': SRV_PORT,
                                    'users': [{'id': UUID, 'encryption': 'none'}]}]},
            'streamSettings': {'network': 'ws', 'security': 'none',
                               'wsSettings': {'path': WS_PATH,
                                              'headers': {'Host': WS_HOST}}},
        }],
    }
    if with_mux:
        cfg['outbounds'][0]['mux'] = {'enabled': True, 'concurrency': 8}
    with open(path, 'w') as f:
        json.dump(cfg, f)


def gen_zig_server_cfg(src_path, dst_path):
    """复制 Zig 服务端配置并把 loglevel 提到 info + access 落临时文件。
    仓库版 xray.json 是 warning 级，M21 的 connection closed / mux session 事件
    都是 Info，不提升级别统计会全是 0（第一次跑就踩到）。"""
    with open(src_path) as f:
        cfg = json.load(f)
    log = cfg.setdefault('log', {})
    log['loglevel'] = 'info'
    log['access'] = dst_path + '.access'
    with open(dst_path, 'w') as f:
        json.dump(cfg, f)


def gen_go_server_cfg(path):
    # 与 Zig 的 xray.json 对齐（19001 VLESS+WS，同 path/Host/UUID）
    cfg = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{
            'tag': 'inbound-19001', 'listen': '0.0.0.0', 'port': SRV_PORT,
            'protocol': 'vless',
            'settings': {'clients': [{'id': UUID, 'email': 'weaknet', 'flow': ''}],
                         'decryption': 'none'},
            'streamSettings': {'network': 'ws', 'security': 'none',
                               'wsSettings': {'path': WS_PATH,
                                              'headers': {'Host': WS_HOST}}},
        }],
        'outbounds': [{'protocol': 'freedom', 'tag': 'direct',
                       'settings': {'finalRules': [{'action': 'allow'}]}}],
    }
    with open(path, 'w') as f:
        json.dump(cfg, f)


def curl_via_socks(url, timeout=40):
    t0 = time.time()
    r = subprocess.run(
        ['curl', '-s', '--max-time', str(timeout), '-o', '-',
         '-x', 'socks5h://%s:%d' % (HOST, SOCKS_PORT), url],
        capture_output=True)
    return r.returncode, r.stdout, time.time() - t0


def pct(vals, p):
    if not vals:
        return 0.0
    s = sorted(vals)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def parse_srv_log(path):
    """从服务端日志提取 connection closed 的 duration 与握手失败计数"""
    durs, hs_fail, dropped, mux_open, mux_close, overload = [], 0, 0, 0, 0, 0
    if not os.path.exists(path):
        return durs, hs_fail, dropped, mux_open, mux_close, overload
    with open(path, 'r', errors='replace') as f:
        for line in f:
            m = re.search(r'connection closed:.*duration=(\d+)ms', line)
            if m:
                durs.append(int(m.group(1)))
            if 'handshake read' in line or 'header read' in line:
                hs_fail += 1
            if 'ws handshake dropped' in line:
                dropped += 1
            if 'mux session opened' in line:
                mux_open += 1
            if 'mux session closed' in line:
                mux_close += 1
            if 'concurrent connections exceed' in line:
                overload += 1
    return durs, hs_fail, dropped, mux_open, mux_close, overload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', choices=['zig', 'go'], default='zig')
    ap.add_argument('--loss', type=int, default=0)
    ap.add_argument('--delay', type=int, default=0)
    ap.add_argument('--jitter', type=int, default=0)
    ap.add_argument('--reorder', type=int, default=0)
    ap.add_argument('--rounds', type=int, default=10, help='小请求次数')
    ap.add_argument('--big', action='store_true', help='额外跑 1MiB')
    ap.add_argument('--big-rounds', type=int, default=3, help='1MiB 轮数（取中位数，弱网下必需）')
    ap.add_argument('--mux', action='store_true', default=True, help='客户端开 mux（默认开）')
    ap.add_argument('--no-mux', dest='mux', action='store_false')
    ap.add_argument('--timeout', type=int, default=40)
    args = ap.parse_args()

    tag = '%s_loss%d_d%d_j%d_r%d' % (args.server, args.loss, args.delay, args.jitter, args.reorder)
    srv_log = '/tmp/ws_weaknet_%s.log' % tag
    cli_log = '/tmp/ws_weaknet_%s_client.log' % tag
    cli_cfg = '/tmp/ws_weaknet_client.json'
    go_srv_cfg = '/tmp/ws_weaknet_go_srv.json'

    target, tport = start_http_target()
    base_url = 'http://%s:%d' % (HOST, tport)
    print('HTTP 靶 %s' % base_url)

    gen_client_cfg(cli_cfg, args.mux)
    if args.server == 'go':
        gen_go_server_cfg(go_srv_cfg)
        srv_bin, srv_cfg = XRAY_GO, go_srv_cfg
    else:
        gen_zig_server_cfg(SERVER_CFG, go_srv_cfg)
        srv_bin, srv_cfg = XRAYZ, go_srv_cfg

    srv = cli = None
    try:
        qdisc_set(args.loss, args.delay, args.jitter, args.reorder)
        with open(srv_log, 'wb') as lf:
            srv = subprocess.Popen([srv_bin, 'run', '-c', srv_cfg], stdout=lf, stderr=subprocess.STDOUT)
        time.sleep(1.5)
        if srv.poll() is not None:
            print('FAIL: 服务端启动即退出，看 %s' % srv_log)
            return 1
        with open(cli_log, 'wb') as lf:
            cli = subprocess.Popen([XRAY_GO, 'run', '-c', cli_cfg], stdout=lf, stderr=subprocess.STDOUT)
        time.sleep(2.0)

        # ---- 小请求 ----
        ok, lat = 0, []
        for i in range(args.rounds):
            rc, body, el = curl_via_socks(base_url + '/', args.timeout)
            good = rc == 0 and body == b'WS-WEAKNET-OK'
            if good:
                ok += 1
                lat.append(el)
            print('  %s 小请求 #%d rc=%d %.2fs' % ('PASS' if good else 'FAIL', i + 1, rc, el))
        print('  小请求 %d/%d，成功延迟 p50=%.2fs p95=%.2fs'
              % (ok, args.rounds, pct(lat, 50), pct(lat, 95)))

        # ---- 1MiB（多轮取中位数：弱网下 TCP 重传时机随机，单次方差可达 50%）----
        big_ok = None
        big_lat = []
        if args.big:
            for i in range(args.big_rounds):
                rc, body, el = curl_via_socks(base_url + '/big', args.timeout)
                good = rc == 0 and len(body) == BIG_LEN and hashlib.sha256(body).hexdigest() == BIG_SHA
                if good:
                    big_lat.append(el)
                print('  %s 1MiB #%d rc=%d len=%d %.2fs'
                      % ('PASS' if good else 'FAIL', i + 1, rc, len(body), el))
            big_ok = len(big_lat) == args.big_rounds
            if big_lat:
                print('  1MiB %d/%d，成功耗时中位数=%.2fs（min=%.2f max=%.2f）'
                      % (len(big_lat), args.big_rounds, pct(big_lat, 50),
                         min(big_lat), max(big_lat)))

        time.sleep(1.0)
        durs, hs_fail, dropped, mux_open, mux_close, overload = parse_srv_log(srv_log)
        print('  服务端日志：connection closed=%d（p50=%dms p95=%dms）握手失败=%d ws_dropped=%d'
              % (len(durs), pct(durs, 50), pct(durs, 95), hs_fail, dropped))
        print('              mux session opened=%d closed=%d  并发拒绝=%d'
              % (mux_open, mux_close, overload))

        ratio = ok / float(args.rounds)
        pass_small = ratio >= (1.0 if args.loss == 0 and args.delay == 0 and args.jitter == 0
                               and args.reorder == 0 else OK_RATIO_WEAK)
        pass_big = True if big_ok is None else big_ok
        verdict = 'PASS' if (pass_small and pass_big) else 'FAIL'
        print('%s %s（小请求 %.0f%% ≥ %.0f%%；1MiB %s）'
              % (verdict, tag, ratio * 100,
                 (100 if args.loss == 0 and args.delay == 0 and args.jitter == 0
                  and args.reorder == 0 else OK_RATIO_WEAK * 100),
                 'ok' if big_ok is None else ('ok' if big_ok else 'FAIL')))
        return 0 if verdict == 'PASS' else 1
    finally:
        qdisc_clear()
        for p in (cli, srv):
            if p and p.poll() is None:
                p.send_signal(signal.SIGTERM)
                try:
                    p.wait(8)
                except Exception:
                    p.kill()
        target.shutdown()


if __name__ == '__main__':
    sys.exit(main())
