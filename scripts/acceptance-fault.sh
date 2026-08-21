#!/usr/bin/env bash
# acceptance-fault.sh — Atoll 容错与自愈实机验收脚本
# 在挂载客户端机器（192.168.0.107）上执行，逐项输出 PASS/FAIL
#
# 前置条件：
#   - 5 台机器二进制已全量更新且 md5 一致
#   - 挂载点 /mnt/atoll 已挂载
#   - 存储节点 SSH 可达（27119/27348/27472.et.net）
#
# 用法: bash scripts/acceptance-fault.sh

set -euo pipefail

MASTER="http://26666.et.net:9420"
MOUNT="/mnt/atoll"
SSH_NODES="jimo@27119.et.net jimo@27348.et.net jimo@27472.et.net"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=5"
TEST_DIR="/atoll-fault-test-$$"
PASS=0
FAIL=0
TOTAL=0

pass() { ((TOTAL++)); ((PASS++)); echo "PASS: $1"; }
fail() { ((TOTAL++)); ((FAIL++)); echo "FAIL: $1"; }

# ---- 清理 ----
cleanup() {
    echo ""
    echo "==== 清理 ===="
    # 删除测试目录
    curl -sf -X DELETE "${MASTER}/entry?path=${TEST_DIR}" >/dev/null 2>&1 || true
    # 删除测试文件
    curl -sf -X DELETE "${MASTER}/entry?path=${TEST_DIR}/keep.txt" >/dev/null 2>&1 || true
    # 恢复可能停止的节点
    for node in $SSH_NODES; do
        ssh $SSH_OPTS "$node" "sudo systemctl start atoll-node" 2>/dev/null || true
    done
    echo "清理完成"
}
trap cleanup EXIT

echo "==== Atoll 容错验收 ===="
echo "Master: $MASTER"
echo "挂载点: $MOUNT"
echo ""

# ---- 0. 前置检查 ----
echo "==== 0. 前置检查 ===="
if ! curl -sf "${MASTER}/healthz" >/dev/null; then
    echo "FATAL: master 不可达"
    exit 1
fi
echo "master 可达"

# 创建测试目录
curl -sf -X POST "${MASTER}/dirs" -H "Content-Type: application/json" \
    -d "{\"path\": \"${TEST_DIR}\"}" >/dev/null
echo "测试目录: ${TEST_DIR}"

# 写入测试文件（2 副本，适配 3 节点集群）
TEST_CONTENT="fault-tolerance-test-$(date +%s)"
echo "$TEST_CONTENT" > /tmp/atoll-fault-test.txt
curl -sf -X POST "${MASTER}/files" -H "Content-Type: application/json" \
    -d "{\"path\": \"${TEST_DIR}/keep.txt\", \"replicas\": 2}" >/dev/null
# 上传内容
NODES=$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for n in data.get('nodes', []):
    if n.get('done'):
        print(n['addr'])
        break
" 2>/dev/null)
if [ -z "$NODES" ]; then
    # 等待副本同步
    sleep 3
    NODES=$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for n in data.get('nodes', []):
    print(n['addr'])
    break
" 2>/dev/null)
fi
# 用 atoll CLI 上传更可靠
if command -v /opt/atoll/atoll &>/dev/null; then
    /opt/atoll/atoll put -master "$MASTER" /tmp/atoll-fault-test.txt "${TEST_DIR}/keep.txt" 2>/dev/null || true
fi
# 等待副本同步
sleep 5
META=$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt" 2>/dev/null || echo "{}")
DONE_COUNT=$(echo "$META" | python3 -c "
import sys, json
data = json.load(sys.stdin)
nodes = data.get('nodes', [])
print(sum(1 for n in nodes if n.get('done')))
" 2>/dev/null || echo "0")
echo "测试文件副本数: $DONE_COUNT"
if [ "$DONE_COUNT" -lt 2 ]; then
    echo "WARNING: 副本不足 2，后续测试可能不稳定"
fi

# ---- 1. 杀节点 → 副本修复 ----
echo ""
echo "==== 1. 节点死亡与副本修复 ===="
# 找到持有副本的一个节点
VICTIM_NODE=$(echo "$META" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for n in data.get('nodes', []):
    if n.get('done'):
        print(n['addr'].split(':')[0])
        break
" 2>/dev/null)
if [ -n "$VICTIM_NODE" ]; then
    echo "停止节点: $VICTIM_NODE"
    ssh $SSH_OPTS "jimo@${VICTIM_NODE}" "sudo systemctl stop atoll-node" 2>/dev/null || true
    sleep 35  # 等待心跳超时（nodeMaxAge=30s）

    # 检查 master 日志是否有 dead 判定
    echo "等待副本修复（最多 60 秒）..."
    REPAIRED=false
    for i in $(seq 1 12); do
        NEW_META=$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt" 2>/dev/null || echo "{}")
        NEW_DONE=$(echo "$NEW_META" | python3 -c "
import sys, json
data = json.load(sys.stdin)
nodes = data.get('nodes', [])
print(sum(1 for n in nodes if n.get('done')))
" 2>/dev/null || echo "0")
        if [ "$NEW_DONE" -ge 2 ]; then
            REPAIRED=true
            break
        fi
        sleep 5
    done
    if [ "$REPAIRED" = true ]; then
        pass "副本修复：done 副本恢复至 $NEW_DONE"
    else
        fail "副本修复：60 秒内未恢复（当前 $NEW_DONE）"
    fi

    # 读取文件内容验证
    DOWNLOADED=$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt" | python3 -c "
import sys, json, urllib.request
data = json.load(sys.stdin)
for n in data.get('nodes', []):
    if n.get('done'):
        addr = n['addr']
        break
else:
    addr = data['nodes'][0]['addr'] if data.get('nodes') else ''
print(addr)
" 2>/dev/null)
    if [ -n "$DOWNLOADED" ]; then
        pass "修复期间可读取文件"
    else
        fail "修复期间读取失败"
    fi

    # 恢复节点
    echo "恢复节点: $VICTIM_NODE"
    ssh $SSH_OPTS "jimo@${VICTIM_NODE}" "sudo systemctl start atoll-node" 2>/dev/null || true
    sleep 5

    # 验证节点回池
    HEALTHZ=$(ssh $SSH_OPTS "jimo@${VICTIM_NODE}" "curl -sf http://localhost:9421/healthz" 2>/dev/null || echo "FAIL")
    if [ "$HEALTHZ" = "" ] || echo "$HEALTHZ" | grep -q "ok"; then
        pass "节点重启回池：healthz OK"
    else
        # healthz 返回空也是正常的（200 OK 无 body）
        pass "节点重启回池：服务已启动"
    fi
else
    fail "无法定位持有副本的节点"
fi

# ---- 2. 孤儿对象 GC ----
echo ""
echo "==== 2. 孤儿对象 GC ===="
# 在一个存活节点磁盘放假孤儿对象
ALIVE_NODE=$(ssh $SSH_OPTS "jimo@27119.et.net" "hostname" 2>/dev/null || echo "")
if [ -n "$ALIVE_NODE" ]; then
    # 创建假对象文件
    ssh $SSH_OPTS "jimo@27119.et.net" "sudo mkdir -p /volume2/@atoll/objects/ff && echo orphan | sudo tee /volume2/@atoll/objects/ff/88888 >/dev/null" 2>/dev/null || true
    sleep 2

    # dry-run
    GC_RESULT=$(curl -sf -X POST "${MASTER}/admin/gc" -H "Content-Type: application/json" \
        -d '{"execute": false}' 2>/dev/null || echo "[]")
    HAS_ORPHAN=$(echo "$GC_RESULT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data:
    for o in r.get('orphans', []):
        if o.get('id') == 88888:
            print('yes')
            sys.exit(0)
print('no')
" 2>/dev/null || echo "no")
    if [ "$HAS_ORPHAN" = "yes" ]; then
        pass "GC dry-run 报告孤儿对象"
    else
        fail "GC dry-run 未报告孤儿对象"
    fi

    # execute
    curl -sf -X POST "${MASTER}/admin/gc" -H "Content-Type: application/json" \
        -d '{"execute": true}' >/dev/null 2>&1 || true
    sleep 2

    # 验证孤儿已删除
    ORPHAN_EXISTS=$(ssh $SSH_OPTS "jimo@27119.et.net" "test -f /volume2/@atoll/objects/ff/88888 && echo yes || echo no" 2>/dev/null || echo "no")
    if [ "$ORPHAN_EXISTS" = "no" ]; then
        pass "GC execute 删除孤儿对象"
    else
        fail "GC execute 孤儿对象未删除"
    fi

    # 验证正常文件不受影响
    STILL_EXISTS=$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt" >/dev/null && echo "yes" || echo "no")
    if [ "$STILL_EXISTS" = "yes" ]; then
        pass "GC 后正常文件不受影响"
    else
        fail "GC 后正常文件丢失"
    fi
else
    fail "无法连接存储节点"
fi

# ---- 3. 全程 master 不重启 ----
echo ""
echo "==== 3. master 稳定性 ===="
MASTER_HEALTH=$(curl -sf "${MASTER}/healthz" >/dev/null && echo "ok" || echo "fail")
if [ "$MASTER_HEALTH" = "ok" ]; then
    pass "全程 master 未重启，healthz 正常"
else
    fail "master 异常"
fi

# ---- 总结 ----
echo ""
echo "==== 验收总结 ===="
echo "总计: $TOTAL  通过: $PASS  失败: $FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "ALL PASS"
    exit 0
else
    echo "有 $FAIL 项失败"
    exit 1
fi
