#!/usr/bin/env python3
# 一键回归（M24）：把散落的验证串成一条命令，输出汇总表。
#
# 覆盖：
#   1. 全量单测（zig test）
#   2. native 构建
#   3. 互通 I1–I5（Go 客户端 ↔ Zig 服务端，含 mux/XUDP/1MiB sha256）
#   4. XUDP smoke（19 项）
#   5. KCP 丢包矩阵（kcp_loss.py，可选 --quick 跳过）
#   6. WS 弱网矩阵（ws_weaknet.py，可选 --quick 跳过）
#
# 用法（打包机）：
#   cd /tmp/xrayz-build
#   python3 tools/regress_all.py              # 全量（约 15–20 分钟）
#   python3 tools/regress_all.py --quick      # 只跑单测+构建+互通+XUDP（约 5 分钟）
#   python3 tools/regress_all.py --only interop,ws
#
# 退出码：0 = 全过；1 = 有失败（明细见表格）。

import argparse
import os
import subprocess
import sys
import time

TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)
ZIG = os.environ.get('ZIG', 'zig')

results = []  # (name, ok, detail, seconds)


def run(name, cmd, timeout, cwd=ROOT, grep=None):
    """跑一条命令；grep 为 None 时用退出码判定，否则在输出里找关键字"""
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=cwd, timeout=timeout,
                           capture_output=True, text=True)
        out = (r.stdout or '') + (r.stderr or '')
        el = time.time() - t0
        if grep:
            ok = any(g in out for g in grep)
            detail = ''
            for line in out.splitlines():
                if any(g in line for g in grep) or 'FAIL' in line or 'passed' in line:
                    detail = line.strip()[:110]
            results.append((name, ok, detail, el))
        else:
            ok = r.returncode == 0
            tail = [l for l in out.splitlines() if l.strip()][-1:] or ['']
            results.append((name, ok, tail[0].strip()[:110], el))
        print('  %s %s (%.1fs)' % ('PASS' if results[-1][1] else 'FAIL', name, el), flush=True)
        return results[-1][1]
    except subprocess.TimeoutExpired:
        results.append((name, False, 'timeout %ds' % timeout, time.time() - t0))
        print('  FAIL %s (timeout %ds)' % (name, timeout), flush=True)
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true', help='跳过丢包/弱网矩阵')
    ap.add_argument('--only', default='', help='逗号分隔：test,build,interop,xudp,kcp,ws')
    ap.add_argument('--seed', default='', help='测试随机种子（复现用）')
    args = ap.parse_args()
    only = set(x.strip() for x in args.only.split(',') if x.strip())

    def want(k):
        return (not only) or (k in only)

    print('=== 一键回归 ===', flush=True)

    if want('test'):
        cmd = [ZIG, 'test', '-lc', 'test_all.zig']
        if args.seed:
            cmd += ['--seed', args.seed]
        run('全量单测', cmd, 600, grep=['passed'])

    if want('build'):
        run('native 构建', [ZIG, 'build'], 600)

    if want('interop'):
        run('互通 I1–I5', [sys.executable, os.path.join(ROOT, 'tests/interop/interop_smoke.py')],
            400, grep=['INTEROP ALL OK'])

    if want('xudp'):
        run('XUDP smoke', [sys.executable, os.path.join(TOOLS, 'xudp_smoke.py')],
            300, grep=['RESULT 19/19'])

    if not args.quick:
        if want('kcp'):
            for L in (0, 5):
                run('KCP 丢包 %d%%' % L,
                    [sys.executable, os.path.join(TOOLS, 'kcp_loss.py'),
                     '--loss', str(L), '--rounds', '3'],
                    500, grep=['KCP LOSS ALL OK', 'ALL OK'])
        if want('ws'):
            for L in (0, 5):
                extra = ['--delay', '100', '--jitter', '20'] if L else []
                run('WS 弱网 %d%%' % L,
                    [sys.executable, os.path.join(TOOLS, 'ws_weaknet.py'),
                     '--server', 'zig', '--loss', str(L), '--rounds', '8',
                     '--big', '--big-rounds', '5'] + extra,
                    500, grep=['PASS zig_loss'])

    print('\n=== 汇总 ===')
    ok_all = True
    for name, ok, detail, el in results:
        print('%-20s %-4s %6.1fs  %s' % (name, 'PASS' if ok else 'FAIL', el, detail))
        ok_all = ok_all and ok
    total = len(results)
    passed = sum(1 for r in results if r[1])
    print('\n%d/%d 通过' % (passed, total))
    return 0 if ok_all else 1


if __name__ == '__main__':
    sys.exit(main())
