#!/bin/sh
# =============================================================================
#  /opt/script/xray_start.sh —— 启动 xray 全局代理（Zig 优先 + Go 回退）
#
#  【路径】：
#    Zig 版  /opt/armbian/bin/xray/xrayz      （M20，md5 d5ef50bc2c9320e84b7f8b630f250e7d）
#    Go  版  /opt/armbian/bin/xray/xray       （回退件，md5 d0edc7394b4f8435c14ee544d786c874）
#    配置    /opt/armbian/bin/xray/xray.json  ★ 两版共用同一份，原地不动
#    日志    /tmp/xrayz.log（Zig）/tmp/xray.log（Go）  ★ tmpfs，重启即丢
#    端口    19001(VLESS+ws, path=/free) / 19002(VMess+KCP)  ★ 不变
#
#  由 /opt/script/user_init.sh 开机调用。幂等：任一版本已运行直接跳过。
#
# -----------------------------------------------------------------------------
#  【启动策略】M21 起 Zig 优先
# -----------------------------------------------------------------------------
#  开机时两版都没跑 → 先起 xrayz，冒烟（进程在 + 19001 TCP + 19002 UDP 都在听）
#  通过则用 Zig 版；任一条件不满足 → 停掉 xrayz，回退 Go 版（原逻辑）。
#  这样"设备重启后静默回落 Go 版"不会再发生，同时保留一键回退安全网。
#
#  若某一版已经在跑（例如刚手工切过），本脚本不改变现状，直接退出 0。
#
# -----------------------------------------------------------------------------
#  【运维手册】更新 / 回滚 / 排障
# -----------------------------------------------------------------------------
#  ⚠ 铁律：二进制【绝不能放 /tmp】（tmpfs，写多少吃 RAM），一律放持久目录。
#      /opt 是 overlay（upperdir=/opt/cu/apps/apps，UBIFS），改动持久。
#
#  ① 手工切回 Go 版（客户端零改动）：
#       /opt/armbian/bin/xray/xrayz-start.sh stop
#       /bin/sh /opt/script/xray_start.sh        # 本脚本会回退起 Go 版
#  ② 手工切到 Zig 版：
#       kill -TERM $(pidof xray) ; /opt/armbian/bin/xray/xrayz-start.sh start
#  ③ 更新 xrayz：传 xrayz.new → md5 核对 → mv → xrayz-start.sh restart
#  ④ 排障入口
#       起不来   → tail -50 /tmp/xrayz.log
#       看端口   → netstat -ltn | grep 19001 ; netstat -lun | grep 19002
#       看资源   → /opt/armbian/bin/xray/xrayz-start.sh status
#       排障日志 → /tmp/xrayz.log（info 级：connection closed / kcp session /
#                  mux session / selfcheck）与 /tmp/xrayz-access.log
# =============================================================================
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

APP_GO=/opt/armbian/bin/xray/xray
APP_ZIG=/opt/armbian/bin/xray/xrayz
ZIG_CTL=/opt/armbian/bin/xray/xrayz-start.sh
CONF=/opt/armbian/bin/xray/xray.json
LOG=/tmp/xray.log

# 精确 exe 比对（绝不用 cmdline 子串匹配：会命中本脚本自身，openlist 踩过的坑）
pid_by_exe() {
    for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        if [ "$(readlink "/proc/$p/exe" 2>/dev/null)" = "$1" ]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

# ---- 1) 幂等：任一版本已在运行就不动 ----
if P=$(pid_by_exe "$APP_ZIG"); then
    echo "[xray_start] zig already running pid=$P"
    exit 0
fi
if P=$(pid_by_exe "$APP_GO"); then
    echo "[xray_start] go already running pid=$P (keep as-is)"
    exit 0
fi

# ---- 2) Zig 优先 ----
if [ -x "$APP_ZIG" ] && [ -x "$ZIG_CTL" ]; then
    /bin/sh "$ZIG_CTL" start >/dev/null 2>&1
    ZPID=""
    i=0
    while [ $i -lt 12 ]; do
        i=$((i + 1))
        sleep 0.3
        ZPID=$(pid_by_exe "$APP_ZIG") || { ZPID=""; continue; }
        if netstat -ltn 2>/dev/null | grep -q ':19001 ' \
           && netstat -lun 2>/dev/null | grep -q ':19002 '; then
            echo "[xray_start] zig version up pid=$ZPID (19001 tcp + 19002 udp)"
            exit 0
        fi
    done
    echo "[xray_start] WARN: zig version failed smoke check (pid=${ZPID:-none}) -> rollback to go"
    echo "[xray_start]       see /tmp/xrayz.log"
    /bin/sh "$ZIG_CTL" stop >/dev/null 2>&1
    sleep 1
else
    echo "[xray_start] xrayz not installed, use go version"
fi

# ---- 3) Go 回退（原逻辑）----
if [ ! -x "$APP_GO" ]; then
    echo "[xray_start] ERR: $APP_GO 不存在或不可执行"
    ls -l /opt/armbian/bin/xray/ 2>/dev/null
    exit 1
fi
[ -f "$CONF" ] || { echo "[xray_start] ERR: 配置 $CONF 不存在"; exit 1; }

cd /opt/armbian/bin/xray || exit 1
nohup "$APP_GO" -c "$CONF" >> "$LOG" 2>&1 &
echo "[xray_start] go version started pid=$!"

