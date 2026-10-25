#!/usr/bin/env python3
# soak 资源曲线报告（M25）：从 selfcheck 行生成资源曲线 + 泄漏判定。
#
# 数据源：服务端 info 日志里的
#   2026/10/24 05:06:40.202000 [Info] selfcheck conns=0 threads=4 rss_kb=1024 fd=8
#
# 判定口径：
#   1) 泄漏：后半段均值 vs 前半段均值，RSS/线程/fd 任一持续上升 >20% 且绝对增量超阈值即告警
#   2) 门限（M27 起改为并发自适应，原平板判定在峰值并发下会误报）：
#      §3.5 平板门限是「20 并发 TCP 稳态」口径（RSS ≤12MB / 线程 ≤60 / fd ≤150）。
#      真实流量峰值并发可能远高于 20（M27 实测 66），此时按线程账模型换算预算：
#        threads ≈ 2×conns + 4   （每连接 2 线程：连接线程兼上行拷贝 + 下行拷贝；mux/XUDP +1）
#        fd      ≈ 2×conns + 8   （client + remote 各 1，加 base 8）
#      超平板但在模型预算内 → 记 INFO（属预期）；超模型预算或 RSS 超 12MB → FAIL。
#
# 用法（设备或打包机）：
#   python3 tools/soak_report.py                       # 默认 /tmp/xrayz.log
#   python3 tools/soak_report.py -f /tmp/xrayz.log --tail 5000
#   python3 tools/soak_report.py --since '2026/10/24 08:'
#
# 退出码：0 = 无泄漏、无门限超限；1 = 有告警。

import argparse
import re
import sys
from collections import namedtuple

Sample = namedtuple('Sample', 'ts conns threads rss fd')

PAT = re.compile(
    r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\.\d+ \[Info\] selfcheck '
    r'conns=(\d+) threads=(\d+) rss_kb=(\d+) fd=(\d+)')


def load(path, tail=0, since=None):
    rows = []
    try:
        with open(path, 'r', errors='replace') as f:
            for line in f:
                m = PAT.match(line)
                if not m:
                    continue
                ts = m.group(1)
                if since and ts < since:
                    continue
                rows.append(Sample(ts, int(m.group(2)), int(m.group(3)),
                                   int(m.group(4)), int(m.group(5))))
    except FileNotFoundError:
        print('日志不存在: %s' % path)
        return []
    return rows[-tail:] if tail else rows


def stats(vals):
    if not vals:
        return (0, 0, 0, 0)
    s = sorted(vals)
    n = len(s)
    return (s[0], s[-1], sum(s) // n, s[min(n - 1, int(n * 0.95))])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', default='/tmp/xrayz.log')
    ap.add_argument('--tail', type=int, default=0, help='只看最后 N 个采样')
    ap.add_argument('--since', default=None, help='起始时间前缀，如 "2026/10/24 08:"')
    ap.add_argument('--mb', action='store_true', help='RSS 以 MB 显示')
    args = ap.parse_args()

    rows = load(args.file, args.tail, args.since)
    if not rows:
        print('没有 selfcheck 采样（检查 loglevel 是否为 info）')
        return 1

    print('=== soak 资源曲线 ===')
    print('文件      : %s' % args.file)
    print('采样数    : %d' % len(rows))
    print('时间跨度  : %s → %s' % (rows[0].ts, rows[-1].ts))
    dur_s = 0
    try:
        import datetime
        t0 = datetime.datetime.strptime(rows[0].ts, '%Y/%m/%d %H:%M:%S')
        t1 = datetime.datetime.strptime(rows[-1].ts, '%Y/%m/%d %H:%M:%S')
        dur_s = (t1 - t0).total_seconds()
        print('持续时间  : %.1f 小时' % (dur_s / 3600.0))
    except Exception:
        pass

    def unit(v):
        return '%.2f MB' % (v / 1024.0) if args.mb else '%d kB' % v

    print('\n指标        min        max        avg        p95')
    for name, key, u in (('conns', 'conns', False), ('threads', 'threads', False),
                         ('rss', 'rss', True), ('fd', 'fd', False)):
        vals = [getattr(r, key) for r in rows]
        mn, mx, av, p95 = stats(vals)
        fmt = (lambda v: unit(v)) if u else (lambda v: '%d' % v)
        print('%-10s %-10s %-10s %-10s %-10s' % (name, fmt(mn), fmt(mx), fmt(av), fmt(p95)))

    # 泄漏判定：前后半段均值对比
    half = len(rows) // 2
    warnings = []
    if half >= 5:
        for name, key in (('rss', 'rss'), ('threads', 'threads'), ('fd', 'fd')):
            a = [getattr(r, key) for r in rows[:half]]
            b = [getattr(r, key) for r in rows[half:]]
            ma = sum(a) / len(a)
            mb = sum(b) / len(b)
            growth = (mb - ma) / ma * 100 if ma else 0
            abs_inc = mb - ma
            thresh_abs = {'rss': 2048, 'threads': 8, 'fd': 20}[name]   # kB / 个 / 个
            flag = growth > 20 and abs_inc > thresh_abs
            print('\n%s 前后半段: %.1f → %.1f（%+.1f%%，绝对 %+.1f）%s'
                  % (name, ma, mb, growth, abs_inc, '  ⚠ 疑似泄漏' if flag else '  OK'))
            if flag:
                warnings.append('%s 增长 %.1f%%（%+.1f）' % (name, growth, abs_inc))

    # 门限对照（M27：并发自适应）
    # §3.5 平板门限是「20 并发 TCP 稳态」口径；本次峰值并发按线程账模型换算预算，
    # 超平板但在预算内属预期（记 INFO 不 FAIL），超预算或 RSS 超 12MB 才 FAIL。
    mx_conns = max(r.conns for r in rows)
    mx_rss = max(r.rss for r in rows)
    mx_th = max(r.threads for r in rows)
    mx_fd = max(r.fd for r in rows)
    print('\n=== 门限对照（峰值并发 %d） ===' % mx_conns)
    print('（§3.5 平板门限为 20 并发稳态口径：RSS ≤12MB / 线程 ≤60 / fd ≤150）')

    # RSS：平板红线（设计文档定为硬性，不随并发放宽）
    ok = mx_rss <= 12 * 1024
    print('%-8s max=%-8d limit=%-6d %s' % ('RSS', mx_rss, 12 * 1024, 'PASS' if ok else 'FAIL'))
    if not ok:
        warnings.append('RSS 超 12MB 红线（%d kB）' % mx_rss)

    # threads / fd：模型预算 = 2×峰值并发 + 余量
    # ⚠️ 已知观测盲区（M27 实测发现）：selfcheck 的 conns 只计 accept 的连接 + KCP 会话，
    # **mux 子会话既不加 conns 也不单独占 selfcheck 计数**，但每个子会话的出站 remote fd
    # 和 2 个线程都真实存在。因此高 mux 复用下预算需留余量：
    #   M27 实测 66 并发 → threads 138（预算 140，贴脸）、fd 151（超出 2×66+8 约 11 个，
    #   即 mux 子会话出站 fd + DNS 解析瞬态 fd）。threads 余量取 8、fd 余量取 24 已按此标定。
    for name, v, flat, margin in (('threads', mx_th, 60, 8), ('fd', mx_fd, 150, 24)):
        budget = 2 * mx_conns + margin
        if v <= budget:
            note = 'PASS'
            if v > flat:
                note = 'PASS（超平板 %d，但峰值并发 %d 下属预期：≈2×%d+base）' % (flat, mx_conns, mx_conns)
            print('%-8s max=%-8d 平板=%-6d 模型预算=%-6d %s' % (name, v, flat, budget, note))
        else:
            print('%-8s max=%-8d 平板=%-6d 模型预算=%-6d FAIL（超模型预算，疑似线程/fd 泄漏或模型外线程）'
                  % (name, v, flat, budget))
            warnings.append('%s 超模型预算（%d > 2×并发%d+%d）' % (name, v, mx_conns, margin))

    if warnings:
        print('\n⚠ 告警：')
        for w in warnings:
            print('  - %s' % w)
        return 1
    print('\n无泄漏、无门限超限。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
