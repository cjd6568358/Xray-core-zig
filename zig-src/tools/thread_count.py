#!/usr/bin/env python3
# 线程数实测：N 个保持连接下的服务端线程数（M24 线程账验证）
# 期望：空闲 4 + 每连接 2（改造后）vs 每连接 3（改造前）
import http.server
import json
import signal
import subprocess
import threading
import time

HOST = '127.0.0.1'
UUID = 'de53e864-8530-4212-a3d7-c31e60b62e91'


class Slow(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(60)          # 挂住，保持连接
        try:
            self.wfile.write(b'x')
        except Exception:
            pass

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer((HOST, 0), Slow)
TPORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

CLI = '/tmp/thr_cli.json'
json.dump({
    'log': {'loglevel': 'warning'},
    'inbounds': [{'tag': 'in', 'listen': HOST, 'port': 10811,
                  'protocol': 'socks', 'settings': {'udp': False}}],
    'outbounds': [{
        'tag': 'vless-ws', 'protocol': 'vless',
        'settings': {'vnext': [{'address': HOST, 'port': 19001,
                                'users': [{'id': UUID, 'encryption': 'none'}]}]},
        'streamSettings': {'network': 'ws', 'security': 'none',
                           'wsSettings': {'path': '/free',
                                          'headers': {'Host': 'ltetp.tv189.com'}}},
    }],
}, open(CLI, 'w'))


def threads(pid):
    try:
        with open('/proc/%d/status' % pid) as f:
            for l in f:
                if l.startswith('Threads:'):
                    return int(l.split()[1])
    except Exception:
        pass
    return -1


zs = subprocess.Popen(['/tmp/xrayz-build/zig-out/bin/xrayz', 'run', '-c', 'xray.json'],
                      cwd='/tmp/xrayz-build',
                      stdout=open('/tmp/thr_srv.log', 'wb'), stderr=subprocess.STDOUT)
time.sleep(1.5)
gc = subprocess.Popen(['/tmp/xray-go-bin', 'run', '-c', CLI],
                      stdout=open('/tmp/thr_cli.log', 'wb'), stderr=subprocess.STDOUT)
time.sleep(2.5)

print('空闲线程数: %d' % threads(zs.pid))

N = 10
procs = []
for _ in range(N):
    procs.append(subprocess.Popen(
        ['curl', '-s', '--max-time', '25', '-o', '/dev/null',
         '-x', 'socks5h://%s:10811' % HOST, 'http://%s:%d/' % (HOST, TPORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
time.sleep(4)
est = subprocess.run(['bash', '-c', "netstat -tn 2>/dev/null | grep -c ':19001'"],
                     capture_output=True, text=True)
print('%d 个保持连接时：线程数=%d，19001 连接数=%s'
      % (N, threads(zs.pid), est.stdout.strip()))
print('（改造后预期 %d；改造前为 %d）' % (4 + 2 * N, 4 + 3 * N))

for p in procs:
    p.kill()
for p in (gc, zs):
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(8)
        except Exception:
            p.kill()
time.sleep(1)
print('收尾后（进程已退出）')
