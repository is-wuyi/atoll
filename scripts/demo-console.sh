#!/usr/bin/env bash
# 一键起 master + 2 节点 + 传个样例分块文件 + console，用来看管理后台效果。
# 用法：
#   bash scripts/demo-console.sh            正常起（全副本健康）
#   bash scripts/demo-console.sh degrade    起完后杀一个节点，制造降级（看完整性页红黄格）
#   bash scripts/demo-console.sh stop        停止全部
set -e
cd "$(dirname "$0")/.."
D=/tmp/atoll-demo
PW=admin1234
# degrade 模式把 node-max-age 调短，杀节点后能较快判死；心跳间隔 5s，故取 8s。
MAXAGE=30s
[ "$1" = "degrade" ] && MAXAGE=8s

if [ "$1" = "stop" ]; then
  pkill -f '/atoll (master|node|console)' 2>/dev/null || true
  echo "已停止 atoll master/node/console。"
  exit 0
fi

echo "==> 清理旧进程与状态"
pkill -f '/atoll (master|node|console)' 2>/dev/null || true
sleep 1
rm -rf "$D"; mkdir -p "$D"

echo "==> 编译 atoll"
go build -o atoll ./cmd/atoll

echo "==> 启动 master (:9450, node-max-age=$MAXAGE)"
nohup ./atoll master -listen :9450 -db "$D/m.db" -node-max-age "$MAXAGE" >"$D/master.log" 2>&1 &
sleep 1

echo "==> 启动 2 个存储节点 (:9451 :9452)"
nohup ./atoll node -listen :9451 -advertise 127.0.0.1:9451 -master http://127.0.0.1:9450 -data-dir "$D/n1" >"$D/n1.log" 2>&1 &
nohup ./atoll node -listen :9452 -advertise 127.0.0.1:9452 -master http://127.0.0.1:9450 -data-dir "$D/n2" >"$D/n2.log" 2>&1 &
sleep 2

echo "==> 上传一个 130MB 样例文件（走分块，2 副本，好看到块×副本矩阵）"
./atoll mkdir -master http://127.0.0.1:9450 /docs || true
head -c 130000000 /dev/urandom > "$D/sample.bin"
./atoll put -master http://127.0.0.1:9450 -replicas 2 "$D/sample.bin" /docs/sample.bin
sleep 2

if [ "$1" = "degrade" ]; then
  echo "==> [degrade] 杀掉 node :9452，制造降级场景"
  pkill -f 'atoll node -listen :9452' 2>/dev/null || true
  echo "    等待 master 判死（约 10s）..."
  sleep 10
fi

echo "==> 创建控制台账号 admin / $PW"
ATOLL_CONSOLE_PASSWORD="$PW" ./atoll console useradd -data-dir "$D/console-data" admin || true

echo "==> 启动 console (:9430)"
nohup ./atoll console -listen :9430 -master http://127.0.0.1:9450 -data-dir "$D/console-data" >"$D/console.log" 2>&1 &
sleep 1

echo ""
echo "================================================================"
echo "  管理后台已就绪：http://127.0.0.1:9430"
echo "  登录： admin / $PW"
[ "$1" = "degrade" ] && echo "  （降级模式：完整性页应显示副本不足的块）"
echo "  停止： bash scripts/demo-console.sh stop"
echo "  日志： $D/*.log"
echo "================================================================"
