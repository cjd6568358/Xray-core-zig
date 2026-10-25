#!/usr/bin/env python3
# syscall 数量对比：Zig vs Go 服务端，一次 1MiB 下行传输
# 目的：M22 测得 Zig 弱网吞吐慢 20-40%，需确认差异是否在系统调用粒度
import http.server
import json
import os
import signal
import subprocess
import threading
import time

HOST = '127.0.0.1'
UUID = 'de53e864-8530-4212-a3d7-c31e60b62e91'
BIG = bytes((i * 31 + 7) & 0xFF for i in range(1024 * 1024))


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


srv_http = http.server.ThreadingHTTPServer((HOST, 0), H)
TPORT = srv_http.server_address[1]
threading.Thread(target=srv_http.serve_forever, daemon=True).start()

CLI_CFG = '/tmp/st_cli.json'
json.dump({
    'log': {'loglevel': 'warning'},
    'inbounds': [{'tag': 'socks-in', 'listen': HOST, 'port': 10809,
                  'protocol': 'socks', 'settings': {'udp': False}}],
    'outbounds': [{
        'tag': 'vless-ws', 'protocol': 'vless',
        'settings': {'vnext': [{'address': HOST, 'port': 19001,
                                'users': [{'id': UUID, 'encryption': 'none'}]}]},
        'streamSettings': {'network': 'ws', 'security': 'none',
                           'wsSettings': {'path': '/free',
                                          'headers': {'Host': 'ltetp.tv189.com'}}},
    }],
}, open(CLI_CFG, 'w'))

ZIG_CFG = '/tmp/st_zig.json'
json.dump({
    'log': {'loglevel': 'warning'},
    'inbounds': [{'tag': 'in', 'listen': '0.0.0.0', 'port': 19001, 'protocol': 'vless',
                  'settings': {'clients': [{'id': UUID, 'email': 'st', 'flow': ''}],
                               'decryption': 'none'},
                  'streamSettings': {'network': 'ws', 'security': 'none',
                                     'wsSettings': {'path': '/free',
                                                    'headers': {'Host': 'ltetp.tv189.com'}}}}],
    'outbounds': [{'protocol': 'freedom', 'tag': 'direct',
                   'settings': {'finalRules': [{'action': 'allow'}]}}],
}, open(ZIG_CFG, 'w'))


def trial(tag, srv_bin, srv_cfg):
    srv = subprocess.Popen([srv_bin, 'run', '-c', srv_cfg],
                           stdout=open('/tmp/st_%s.log' % tag, 'wb'),
                           stderr=subprocess.STDOUT)
    time.sleep(1.5)
    if srv.poll() is not None:
        print('%s: server exited' % tag)
        return
    cli = subprocess.Popen(['/tmp/xray-go-bin', 'run', '-c', CLI_CFG],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.0)
    # 预热一次（避免握手 syscall 混入统计）
    subprocess.run(['curl', '-s', '--max-time', '20', '-o', '/dev/null',
                    '-x', 'socks5h://%s:10809' % HOST,
                    'http://%s:%d/' % (HOST, TPORT)], capture_output=True)
    time.sleep(0.3)

    st = subprocess.Popen(['strace', '-c', '-f', '-p', str(srv.pid),
                           '-o', '/tmp/st_%s.txt' % tag],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.6)
    t0 = time.time()
    r = subprocess.run(['curl', '-s', '--max-time', '60', '-o', '/dev/null',
                        '-w', '%{size_download}',
                        '-x', 'socks5h://%s:10809' % HOST,
                        'http://%s:%d/big' % (HOST, TPORT)], capture_output=True)
    el = time.time() - t0
    time.sleep(0.4)
    st.send_signal(signal.SIGINT)
    try:
        st.wait(5)
    except Exception:
        st.kill()

    print('\n=== %s：1MiB %.3fs size=%s ===' % (tag, el, r.stdout.decode().strip()))
    try:
        with open('/tmp/st_%s.txt' % tag) as f:
            lines = [l.rstrip() for l in f if l.strip()]
        # 只打关心的行
        for l in lines:
            if any(k in l for k in ('read', 'write', 'sendto', 'recvfrom', 'sendmsg',
                                    'recvmsg', 'setsockopt', 'epoll', 'futex', 'total')):
                print('  ' + l)
    except Exception as e:
        print('  (no strace output: %r)' % e)

    for p in (cli, srv):
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(8)
            except Exception:
                p.kill()
    time.sleep(0.5)


trial('zig', '/tmp/xrayz-build/zig-out/bin/xrayz', ZIG_CFG)
trial('go', '/tmp/xray-go-bin', ZIG_CFG)
