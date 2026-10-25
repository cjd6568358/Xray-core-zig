#!/bin/sh
# xrayz 启动脚本（info 日志 + access 落盘 + 双日志轮转）—— M28 修订
# 用法：/opt/armbian/bin/xray/xrayz-start.sh [start|stop|restart|status|rotate|archive]
#
# 日志（都在 tmpfs /tmp，**重启即丢**，属预期；复盘要在重启前拉走）：
#   /tmp/xrayz.log          主日志（Info：connection closed / kcp session / mux session / selfcheck）
#   /tmp/xrayz-access.log   access 日志（每请求一行）
#
# 轮转（M28 起，复盘向）：
#   - start 时按大小自动归档（主日志 20MB / access 10MB 阈值）
#   - `rotate` / `archive`：无条件归档当前日志并原址截断（cron 每日 04:00 调用，
#     见 root crontab：`0 4 * * * /opt/armbian/bin/xray/xrayz-start.sh archive`）
#   - ⚠️ 必须 **copy-truncate**（先 cp 归档再 `: >` 原文件）：程序只写 stderr，
#     fd 由 shell 重定向（`>> "$LOG" 2>&1`）持有；若用 mv，后续日志会继续写进
#     被移走的 inode、新文件永远不会出现（M28 修订前正是此缺陷）。
#   - 归档命名 `xrayz.log.YYYYmmdd-HHMM`，只保留最近 KEEP 份（每日一份 ≈ 两周）。
#   - cp 与截断之间有毫秒级写入丢失窗口（低峰期调用可忽略）。
DIR=/opt/armbian/bin/xray
CFG=$DIR/xray.json
LOG=/tmp/xrayz.log
ACCESS=/tmp/xrayz-access.log
MAXLOG=$((20 * 1024 * 1024))    # 主日志归档阈值 20MB
MAXACC=$((10 * 1024 * 1024))    # access 归档阈值 10MB
KEEP=14                          # 归档保留份数（每日一份 ≈ 两周）

rotate_one() {
    f=$1
    max=$2
    force=$3
    [ -f "$f" ] || return 0
    SZ=$(stat -c %s "$f" 2>/dev/null || echo 0)
    if [ "$force" = "force" ] || [ "$SZ" -gt "$max" ]; then
        STAMP=$(date +%Y%m%d-%H%M)
        DST="$f.$STAMP"
        n=1
        while [ -e "$DST" ]; do DST="$f.$STAMP.$n"; n=$((n + 1)); done
        if cp "$f" "$DST" && : > "$f"; then
            echo "archived $f ($SZ bytes -> ${DST##*/})"
        else
            echo "archive FAILED: $f" >&2
            return 1
        fi
        # 保留最近 KEEP 份，删更早的
        ls -1t "$f".2* 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
            rm -f "$old" && echo "pruned ${old##*/}"
        done
    fi
}

log_rotate() {   # 大小触发（start 时用）
    rotate_one "$LOG" "$MAXLOG"
    rotate_one "$ACCESS" "$MAXACC"
}

log_archive() {  # 无条件归档（cron 每日 / 手工 rotate 用）
    rotate_one "$LOG" "$MAXLOG" force
    rotate_one "$ACCESS" "$MAXACC" force
}

start() {
    if [ -n "$(pidof xrayz)" ]; then echo "already running: $(pidof xrayz)"; return 0; fi
    log_rotate
    cd "$DIR"
    nohup ./xrayz run -c "$CFG" >> "$LOG" 2>&1 &
    sleep 1
    echo "started pid=$(pidof xrayz)"
}

stop() {
    PID=$(pidof xrayz)
    if [ -z "$PID" ]; then echo "not running"; return 0; fi
    kill -TERM $PID
    for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 $PID 2>/dev/null || break; sleep 0.5; done
    kill -0 $PID 2>/dev/null && echo "still running after TERM" || echo "stopped"
}

status() {
    PID=$(pidof xrayz)
    if [ -z "$PID" ]; then echo "not running"; return 1; fi
    echo "pid=$PID"
    grep -E "^(Threads|VmRSS)" /proc/$PID/status
    echo "--- listeners ---"
    netstat -ltn 2>/dev/null | grep -E ":19001"
    netstat -lun 2>/dev/null | grep -E ":19002"
    echo "--- active conns ---"
    netstat -tn 2>/dev/null | grep -c ":19001"
    echo "--- logs ---"
    ls -la "$LOG" "$ACCESS" 2>/dev/null
    ls -1t "$LOG".2* "$ACCESS".2* 2>/dev/null | head -5 | sed 's/^/  archive: /'
    echo "--- recent log ---"
    tail -5 "$LOG"
}

case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; start ;;
    status)  status ;;
    rotate|archive) log_archive ;;
    *)       echo "usage: $0 [start|stop|restart|status|rotate|archive]" ;;
esac
