#!/usr/bin/env python3
# commute_report.py — 通勤时段复盘工具（M28）
#
# 用途：用户报"上下班某时段用着有问题"时，把该时间窗内的服务端日志汇成一份诊断报告：
#   连接时长分布 / 短命连接率 / mux 会话配对 / KCP 重传统计 / 握手与拨号错误 /
#   overload 拒绝 / selfcheck 资源曲线 / access 请求统计 + 启发式结论。
#
# 时间基准：`--tz` = "日志时间戳相对本地时间的偏移小时数"（默认 8），分两段口径：
#   · M33 之前：applog 按 **UTC** 输出（设备本地 CST=UTC+8，日志比本地慢 8h）→ 用默认 --tz 8
#   · M33 起  ：applog 按 **本地时区** 输出（读 TZ / /etc/TZ，与 Go 版一致）→ 用 --tz 0
#   --from/--to 始终按本地时间给，工具内部换算后匹配时间戳前缀。
#
# 用法：
#   python3 tools/commute_report.py -f /tmp/xrayz.log \
#       [--from '08:00' --to '09:30'] [--tz 8] [-a /tmp/xrayz-access.log]
#   # --from/--to 接受 'HH:MM'（当天本地）、'YYYY-MM-DD HH:MM'、'YYYY-MM-DD'
#   # 不给窗口 = 分析整个文件
#
# 退出码：0 = 窗口内无"严重"级发现；1 = 有（撞上限/重连风暴/疑似泄漏），可接自动化。
#
# 日志行格式（解析锚点，改格式需同步改本工具）：
#   ... [Info] connection closed: from=IP:port tag=T transport=TR protocol=PR duration=Nms
#   ... [Info] mux session opened: id=N dest_port=N from=IP:port
#   ... [Info] mux session closed: id=N dest_port=N duration=Nms
#   ... [Info] kcp session opened: conv=N from=IP:port
#   ... [Info] kcp session closed: conv=N duration=Nms sent=N retrans=N rto=Nms   # M28 起带统计
#   ... [Warning] vless/vmess handshake read <err> from <src>
#   ... [Warning] ws handshake dropped (read/parse failure) from <src>
#   ... [Warning] rejecting connection from <src>: concurrent connections exceed limit N (active=N)
#   ... [Info] selfcheck conns=N threads=N rss_kb=N fd=N
#   access: ...  from IP:port accepted tcp|udp:host:port [in >> out] email: user

import argparse
import re
import sys
from collections import Counter, defaultdict

TS = r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'

RE_CONN_CLOSED = re.compile(
    TS + r'.*connection closed: from=(\S+) tag=(\S+) transport=(\S+) protocol=(\S+) duration=(\d+)ms')
RE_MUX_OPEN = re.compile(TS + r'.*mux session opened: id=(\d+) dest_port=(\d+)(?: from=(\S+))?')
RE_MUX_CLOSE = re.compile(
    TS + r'.*mux session closed: id=(\d+) dest_port=(\d+)(?: from=(\S+))? duration=(\d+)ms')
RE_KCP_OPEN = re.compile(TS + r'.*kcp session opened: conv=(\d+)')
RE_KCP_CLOSE = re.compile(
    TS + r'.*kcp session closed: conv=(\d+) duration=(\d+)ms'
    r'(?: sent=(\d+) retrans=(\d+) rto=(\d+)ms)?')      # M28 起带统计；旧格式无后缀
RE_SELFCHECK = re.compile(
    TS + r'.*selfcheck conns=(\d+) threads=(\d+) rss_kb=(\d+) fd=(\d+)')
RE_OVERLOAD = re.compile(TS + r'.*exceed limit (\d+) \(active=(\d+)\)')
RE_WARN = re.compile(TS + r'.*\[(Warning|Error)\] (.*)')
# access 行带微秒（"2026/10/24 14:03:01.980000  from ..."）——TS 后必须容忍 \S*，
# 否则整节恒为 0（M31 生产日志实测发现）。
RE_ACCESS = re.compile(
    TS + r'\S*\s+from (\S+) accepted (tcp|udp):(\S+) \[([^\]]+)\] email: (\S+)')

# 告警模板归一化：把 IP/端口/数字/邮箱换成占位符，让同类告警合并计数
def normalize(msg):
    msg = re.sub(r'\d+\.\d+\.\d+\.\d+(:\d+)?', '<addr>', msg)
    msg = re.sub(r'\b\d+\b', 'N', msg)
    return msg[:70]


def parse_window(s, tz):
    """把本地时间窗解析成 (起, 止) 的 UTC 字符串对（含端点，按字典序比较时间戳前缀）。"""
    if not s:
        return None
    import datetime
    now = datetime.datetime.now()
    s = s.strip()
    for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            t = datetime.datetime.strptime(s, fmt)
            break
        except ValueError:
            continue
    else:
        if re.fullmatch(r'\d{1,2}:\d{2}', s):
            h, m = s.split(':')
            t = now.replace(hour=int(h), minute=int(m), second=0, microsecond=0)
        else:
            raise SystemExit('无法解析时间: %r（支持 HH:MM / YYYY-MM-DD HH:MM / YYYY-MM-DD）' % s)
    u = t - datetime.timedelta(hours=tz)          # 本地 → UTC
    return u.strftime('%Y/%m/%d %H:%M:%S')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', default='/tmp/xrayz.log', help='主日志')
    ap.add_argument('-a', '--access', default=None, help='access 日志（可选）')
    ap.add_argument('--from', dest='frm', default=None, help='起始（本地时间）')
    ap.add_argument('--to', default=None, help='结束（本地时间）')
    ap.add_argument('--tz', type=int, default=8, help='本地时区偏移（默认 +8）')
    args = ap.parse_args()

    lo = parse_window(args.frm, args.tz)
    hi = parse_window(args.to, args.tz)

    def in_window(ts):
        if lo and ts < lo:
            return False
        if hi and ts > hi:
            return False
        return True

    conn_closed = []           # (ts, dur_ms, transport, protocol)
    mux_open = []              # (id, from)
    mux_close = []             # (id, from, dur)
    kcp_open, kcp_close = [], []
    kcp_stats = []             # (dur, sent, retrans, rto)
    selfcheck = []             # (ts, conns, threads, rss, fd)
    overload = 0
    warns = Counter()          # 归一化模板 -> 次数
    warn_samples = defaultdict(list)
    access = []                # (ts, src, proto, dest, email)

    nlines = 0
    try:
        with open(args.file, 'r', errors='replace') as f:
            for line in f:
                nlines += 1
                m = RE_CONN_CLOSED.search(line)
                if m and in_window(m.group(1)):
                    conn_closed.append((m.group(1), int(m.group(6)), m.group(4), m.group(5)))
                    continue
                m = RE_MUX_OPEN.search(line)
                if m and in_window(m.group(1)):
                    mux_open.append((m.group(2), m.group(4)))   # (id, from)
                    continue
                m = RE_MUX_CLOSE.search(line)
                if m and in_window(m.group(1)):
                    mux_close.append((m.group(2), m.group(4), int(m.group(5))))  # (id, from, dur)
                    continue
                m = RE_KCP_OPEN.search(line)
                if m and in_window(m.group(1)):
                    kcp_open.append(m.group(1))
                    continue
                m = RE_KCP_CLOSE.search(line)
                if m and in_window(m.group(1)):
                    kcp_close.append((int(m.group(3)), m.group(4), m.group(5), m.group(6)))
                    continue
                m = RE_SELFCHECK.search(line)
                if m and in_window(m.group(1)):
                    selfcheck.append((m.group(1), int(m.group(2)), int(m.group(3)),
                                      int(m.group(4)), int(m.group(5))))
                    continue
                m = RE_OVERLOAD.search(line)
                if m and in_window(m.group(1)):
                    overload += 1
                    continue
                m = RE_WARN.search(line)
                if m and in_window(m.group(1)):
                    tpl = normalize(m.group(3))
                    warns[tpl] += 1
                    if len(warn_samples[tpl]) < 2:
                        warn_samples[tpl].append(line.strip()[:120])
                    continue
    except FileNotFoundError:
        print('日志不存在: %s' % args.file)
        return 1

    if args.access:
        try:
            with open(args.access, 'r', errors='replace') as f:
                for line in f:
                    m = RE_ACCESS.search(line)
                    if m and in_window(m.group(1)):
                        access.append((m.group(1), m.group(2), m.group(3), m.group(4), m.group(6)))
        except FileNotFoundError:
            print('（access 日志不存在: %s，跳过）' % args.access)

    severe, warn_level = [], []

    # ---------- 报告 ----------
    print('=' * 62)
    print('通勤时段复盘报告')
    print('日志      : %s（%d 行）' % (args.file, nlines))
    if lo or hi:
        import datetime
        def back(u):   # UTC → 本地显示
            if not u:
                return '（开头）'
            t = datetime.datetime.strptime(u, '%Y/%m/%d %H:%M:%S') + datetime.timedelta(hours=args.tz)
            return t.strftime('%Y-%m-%d %H:%M:%S')
        src = '本地时区' if args.tz == 0 else 'UTC'
        print('时间窗    : %s → %s（本地 UTC%+d；日志时间戳为%s，已换算）' % (back(lo), back(hi), args.tz, src))
    print('=' * 62)

    # 1) 连接关闭
    print('\n【1】连接关闭 %d 条' % len(conn_closed))
    if conn_closed:
        buckets = Counter()
        for _, dur, _, _ in conn_closed:
            if dur < 1000: buckets['<1s'] += 1
            elif dur < 5000: buckets['1-5s'] += 1
            elif dur < 30000: buckets['5-30s'] += 1
            elif dur < 300000: buckets['30-300s'] += 1
            else: buckets['>300s'] += 1
        total = len(conn_closed)
        short_rate = buckets['<1s'] * 100.0 / total
        print('  时长分布: ' + '  '.join('%s=%d(%.0f%%)' % (k, v, v * 100.0 / total)
                                        for k, v in [('<1s', buckets['<1s']), ('1-5s', buckets['1-5s']),
                                                     ('5-30s', buckets['5-30s']), ('30-300s', buckets['30-300s']),
                                                     ('>300s', buckets['>300s'])]))
        tp = Counter('%s/%s' % (t, p) for _, _, t, p in conn_closed)
        print('  传输/协议: ' + ', '.join('%s=%d' % kv for kv in tp.most_common()))
        print('  短命连接(<1s)占比: %.1f%%' % short_rate)
        if short_rate > 30 and total >= 50:
            severe.append('短命连接率 %.0f%%（%d/%d）——疑似客户端重连风暴（弱网/被拒后的反复重试）'
                          % (short_rate, buckets['<1s'], total))
        elif short_rate > 50:
            warn_level.append('短命连接率 %.0f%%，样本较少，观察即可' % short_rate)

    # 2) mux 会话
    opened_n, closed_n = len(mux_open), len(mux_close)
    print('\n【2】mux 会话 opened=%d closed=%d' % (opened_n, closed_n))
    if opened_n or closed_n:
        has_from = bool(mux_close) and all(f for _, f, _ in mux_close)
        if has_from:
            # 精确配对：id 在每个 mux 连接内从 1 重新计数，必须按 (from, id) 二元组
            opened_ct = Counter(mux_open)
            closed_ct = Counter((i, f) for i, f, _ in mux_close)
            unpaired = {k: opened_ct[k] - closed_ct.get(k, 0)
                        for k in opened_ct if opened_ct[k] != closed_ct.get(k, 0)}
            if unpaired:
                print('  ⚠ (from,id) 未配对: %s' % dict(list(unpaired.items())[:8]))
                gap = opened_n - closed_n
                if abs(gap) > max(5, opened_n * 0.1):
                    severe.append('mux 会话 opened-closed=%d（未配对 %d 组）——疑似会话泄漏/悬挂'
                                  % (gap, len(unpaired)))
                else:
                    warn_level.append('mux 会话差 %d（可能是窗口边界处仍在活跃的会话）' % gap)
            else:
                print('  配对完整 ✓')
        else:
            # 旧版日志关闭行无 from=：id 跨连接重复，只能聚合比总数
            gap = opened_n - closed_n
            print('  （关闭行无 from= 字段=旧版日志；id 跨 mux 连接会重复，只能聚合比对）')
            if abs(gap) > max(5, opened_n * 0.1):
                severe.append('mux 会话 opened-closed=%d——疑似会话泄漏/悬挂（M28+ 可按 from= 精确配对）' % gap)
            elif gap > 0:
                warn_level.append('mux 会话 opened 比 closed 多 %d（可能是窗口边界处仍在活跃的会话）' % gap)
            else:
                print('  聚合配对完整 ✓')
        if mux_close:
            durs = sorted(d for _, _, d in mux_close)
            print('  会话时长: min=%dms 中位=%dms max=%dms'
                  % (durs[0], durs[len(durs) // 2], durs[-1]))

    # 3) KCP 会话
    print('\n【3】KCP 会话 opened=%d closed=%d' % (len(kcp_open), len(kcp_close)))
    if kcp_close:
        with_retrans = [k for k in kcp_close if k[2] and int(k[2]) > 0]
        if any(k[2] for k in kcp_close):
            tot_sent = sum(int(k[1]) for k in kcp_close if k[1])
            tot_ret = sum(int(k[2]) for k in kcp_close if k[2])
            print('  带重传的会话: %d/%d（%.0f%%）' % (len(with_retrans), len(kcp_close),
                                                      len(with_retrans) * 100.0 / len(kcp_close)))
            print('  总发送段=%d 总重传段=%d（重传比 %.1f%%）' % (tot_sent, tot_ret,
                                                                 (tot_ret * 100.0 / tot_sent) if tot_sent else 0))
            rtos = [int(k[3]) for k in kcp_close if k[3]]
            if rtos:
                print('  关闭时 RTO: min=%dms 中位=%dms max=%dms'
                      % (min(rtos), sorted(rtos)[len(rtos) // 2], max(rtos)))
            ratio = len(with_retrans) * 100.0 / len(kcp_close)
            if ratio > 20 or (tot_sent and tot_ret * 100.0 / tot_sent > 10):
                warn_level.append('KCP 重传比例高（%.0f%% 会话有重传，总重传比 %.1f%%）——链路丢包'
                                  % (ratio, (tot_ret * 100.0 / tot_sent) if tot_sent else 0))
        else:
            print('  （旧版二进制：无 sent/retrans 字段；升级到 M28+ 后此处才有弱网证据）')

    # 4) 握手/错误
    print('\n【4】握手与错误告警 %d 条' % sum(warns.values()))
    for tpl, n in warns.most_common(10):
        print('  [%3d] %s' % (n, tpl))
        if n >= 1 and len(warn_samples[tpl]) == 1:
            print('         e.g. %s' % warn_samples[tpl][0])
    hs = sum(n for t, n in warns.items() if 'handshake' in t)
    if hs >= 10:
        warn_level.append('握手失败 %d 次——弱网半包头/客户端放弃或服务端异常，看具体模板' % hs)

    # 5) overload
    print('\n【5】并发上限拒绝: %d 次' % overload)
    if overload > 0:
        severe.append('overload 拒绝 %d 次——新连接被直接关闭，用户体感"丢包/连不上"' % overload)

    # 6) selfcheck
    print('\n【6】selfcheck 采样 %d 个' % len(selfcheck))
    if selfcheck:
        mx_c = max(s[1] for s in selfcheck)
        mx_t = max(s[2] for s in selfcheck)
        mx_r = max(s[3] for s in selfcheck)
        mx_f = max(s[4] for s in selfcheck)
        print('  峰值: conns=%d threads=%d rss=%dkB(%0.1fMB) fd=%d'
              % (mx_c, mx_t, mx_r, mx_r / 1024.0, mx_f))
        over_t = [s for s in selfcheck if s[2] > 2 * s[1] + 8]
        over_f = [s for s in selfcheck if s[4] > 2 * s[1] + 24]
        over_r = [s for s in selfcheck if s[3] > 12 * 1024]
        if over_t or over_f or over_r:
            print('  ⚠ 超模型预算采样: threads %d 个 / fd %d 个 / RSS %d 个'
                  % (len(over_t), len(over_f), len(over_r)))
            if opened_n > 0:
                # 已知盲区：selfcheck 的 conns 只计 accept 连接 + KCP 会话，
                # mux 子会话的 2 线程 + 1 出站 fd 不计入 → 高复用下必然"超预算"
                print('  （窗口内有 mux 会话 %d 个——conns 不含子会话数，超预算很可能由此而来，'
                      '见设计文档 §3.5 观测盲区登记）' % opened_n)
                warn_level.append('selfcheck 超模型预算采样 threads %d/fd %d/rss %d 个；'
                                  '窗口内有 mux 会话，疑为子会话不计入 conns 的盲区所致'
                                  % (len(over_t), len(over_f), len(over_r)))
            else:
                warn_level.append('selfcheck 有采样超线程/fd/RSS 预算且无 mux 会话——需警惕真实泄漏'
                                  '（threads %d/fd %d/rss %d 个）' % (len(over_t), len(over_f), len(over_r)))
        else:
            print('  全部在模型预算内 ✓（threads≤2×conns+8, fd≤2×conns+24, rss≤12MB）')

    # 7) access
    if args.access:
        print('\n【7】access 请求 %d 条' % len(access))
        if access:
            hosts = Counter()
            for _, _, _, dest, _ in access:
                h = dest.rsplit(':', 1)[0] if dest.count(':') >= 1 else dest
                hosts[h] += 1
            print('  top 目标: ' + ', '.join('%s=%d' % kv for kv in hosts.most_common(8)))
            protos = Counter(p for _, _, p, _, _ in access)
            print('  协议分布: ' + ', '.join('%s=%d' % kv for kv in protos.most_common()))

    # ---------- 结论 ----------
    print('\n' + '=' * 62)
    print('诊断结论')
    print('=' * 62)
    if severe:
        for s in severe:
            print('  [严重] %s' % s)
    for w in warn_level:
        print('  [警告] %s' % w)
    if not severe and not warn_level:
        print('  窗口内无明显异常（无重连风暴/无撞上限/无泄漏迹象/无显著错误）。')
    if severe:
        print('\n建议：先看 [严重] 项对应的日志样本（报告第 4 节有 e.g. 行），'
              '再结合该时段 selfcheck 曲线判断是链路问题还是服务端问题。')
    return 1 if severe else 0


if __name__ == '__main__':
    sys.exit(main())
