#!/usr/bin/env bash
# acceptance-fault.sh — Atoll 容错与自愈实机验收脚本
# 在挂载客户端机器（192.168.0.107）上执行，逐项输出 PASS/FAIL
#
# 前置条件：
#   - 各机器二进制已全量更新且 md5 一致
#   - atoll CLI 在 PATH 中（/usr/local/bin/atoll）
#   - 存储节点 jimo 账户已配置 sudoers NOPASSWD（systemctl atoll-node，
#     见 /etc/sudoers.d/atoll-acceptance），否则杀节点步骤会假 PASS
#   - 27348.et.net 当前关机，已排除；3 节点齐全时本脚本自动验证"换机重建副本"
#
# 2 节点集群（2 副本）下的预期语义：
#   杀 1 台后无候选目标 → spec 规定 SkipNoTarget：dead 节点保留在 Replicas，
#   重启回池后旧副本直接复用，done 恢复至 2。
# 3 节点集群下：杀 1 台 → 副本换机重建，done 恢复至 2。
#
# 用法: ATOLL_MASTER=http://26666.et.net:9420 bash acceptance-fault.sh

set -uo pipefail

MASTER="${ATOLL_MASTER:-http://26666.et.net:9420}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes"
TEST_DIR="/atoll-fault-test-$$"
FAKE_INODE=987654
PASS=0; FAIL=0; TOTAL=0

pass() { ((TOTAL++)); ((PASS++)); echo "PASS: $1"; }
fail() { ((TOTAL++)); ((FAIL++)); echo "FAIL: $1"; }

# ---- JSON 辅助 ----
count_done() { echo "$1" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(sum(1 for n in (d.get('nodes') or []) if n.get('done')))" 2>/dev/null || echo 0; }

node_addrs() { echo "$1" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(' '.join(n['addr'].split(':')[0] for n in (d.get('nodes') or [])))" 2>/dev/null; }

replicas_count() { echo "$1" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(len(d['inode'].get('replicas') or []))" 2>/dev/null || echo 0; }

cleanup() {
    echo ""
    echo "==== 清理 ===="
    for node in 27119.et.net 27472.et.net; do
        ssh $SSH_OPTS "jimo@$node" "sudo -n systemctl start atoll-node" >/dev/null 2>&1 || true
    done
    curl -sf -X DELETE "${MASTER}/entry?path=${TEST_DIR}" >/dev/null 2>&1 || true
    echo "清理完成"
}
trap cleanup EXIT

echo "==== Atoll 容错验收 ===="
echo "Master: $MASTER"
echo ""

# ---- 0. 前置检查 ----
echo "==== 0. 前置检查 ===="
if ! curl -sf "${MASTER}/healthz" >/dev/null; then
    echo "FATAL: master 不可达"; exit 1
fi
echo "master 可达"

# SSH + sudo 免密探活：不通则杀节点测试必然失效，直接终止
NODES_OK=true
for node in 27119.et.net 27472.et.net; do
    if ! ssh $SSH_OPTS "jimo@$node" "sudo -n systemctl is-active atoll-node" 2>/dev/null | grep -q active; then
        echo "FATAL: $node SSH 或 sudo NOPASSWD 不可用（或服务未运行）"
        NODES_OK=false
    fi
done
[ "$NODES_OK" = true ] || exit 1
echo "存储节点 SSH + sudo NOPASSWD 可用"

curl -sf -X POST "${MASTER}/dirs" -H "Content-Type: application/json" \
    -d "{\"path\": \"${TEST_DIR}\"}" >/dev/null
echo "测试目录: ${TEST_DIR}"

TEST_CONTENT="fault-tolerance-test-$(date +%s)"
echo "$TEST_CONTENT" > /tmp/atoll-fault-test.txt
export ATOLL_MASTER="$MASTER"
if ! atoll put -replicas 2 /tmp/atoll-fault-test.txt "${TEST_DIR}/keep.txt"; then
    echo "FATAL: 上传测试文件失败"; exit 1
fi
sleep 5  # 等副本同步

META=$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt")
DONE0=$(count_done "$META")
echo "测试文件 done 副本数: $DONE0"
if [ "$DONE0" -ge 2 ]; then pass "初始 2 副本就绪"; else fail "初始副本不足 2（${DONE0}）"; fi

# ---- 1. 杀节点 → 判死 → 修复 → 回池 ----
echo ""
echo "==== 1. 节点死亡与副本修复 ===="
VICTIM=$(echo "$META" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for n in (d.get('nodes') or []):
    if n.get('done'):
        print(n['addr'].split(':')[0]); break" 2>/dev/null)

if [ -z "$VICTIM" ]; then
    fail "无法定位持有副本的节点"
else
    echo "停止节点: $VICTIM"
    ssh $SSH_OPTS "jimo@$VICTIM" "sudo -n systemctl stop atoll-node" >/dev/null 2>&1
    sleep 2
    # 关键防假 PASS：确认节点真的停了
    if curl -sf --connect-timeout 3 "http://${VICTIM}:9421/healthz" >/dev/null 2>&1; then
        fail "节点停止失败（healthz 仍可达），后续修复验证无效"
    else
        pass "节点已真实停止（healthz 不可达）"
        sleep 35  # 等心跳超时（nodeMaxAge=30s）+ 判死扫描（10s 周期）

        # 1a. 判死生效：/meta 不再返回该节点
        M=$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt")
        if node_addrs "$M" | tr ' ' '\n' | grep -qx "$VICTIM"; then
            fail "判死未生效：/meta 仍返回 $VICTIM"
        else
            pass "master 判死生效（/meta 已移除 ${VICTIM}）"
        fi

        # 1b. 修复期间读文件无感知：真实下载并比对内容
        if atoll get "${TEST_DIR}/keep.txt" /tmp/atoll-fault-got.txt 2>/dev/null \
            && cmp -s /tmp/atoll-fault-test.txt /tmp/atoll-fault-got.txt; then
            pass "修复期间读取无感知（内容一致）"
        else
            fail "修复期间读取失败或内容不一致"
        fi

        # 1c. 修复扫描（15s 周期）：
        #     3 节点集群 → done 换机重建回 2
        #     2 节点集群 → 无候选目标，spec SkipNoTarget：dead 保留在 Replicas
        echo "等待修复扫描（最多 60 秒）..."
        REPAIRED=false; i=0; M2="$M"
        while [ $i -lt 12 ]; do
            M2=$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt")
            if [ "$(count_done "$M2")" -ge 2 ]; then REPAIRED=true; break; fi
            sleep 5; i=$((i+1))
        done
        RKEPT=$(replicas_count "$M2")
        if [ "$REPAIRED" = true ]; then
            pass "副本修复：done 副本恢复至 2（换机重建）"
        elif [ "$RKEPT" -eq 2 ]; then
            pass "无候选目标：dead 槽保留在 Replicas（SkipNoTarget，2 节点集群预期行为）"
        else
            fail "副本修复异常：done 未恢复且 Replicas 数异常（${RKEPT}）"
        fi

        # 1d. 重启回池：心跳恢复 → done 回 2（旧副本直接复用）
        echo "恢复节点: $VICTIM"
        ssh $SSH_OPTS "jimo@$VICTIM" "sudo -n systemctl start atoll-node" >/dev/null 2>&1
        echo "等待回池与副本确认（最多 90 秒）..."
        BACK=false; i=0
        while [ $i -lt 18 ]; do
            M3=$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt")
            if node_addrs "$M3" | tr ' ' '\n' | grep -qx "$VICTIM" \
                && [ "$(count_done "$M3")" -ge 2 ]; then
                BACK=true; break
            fi
            sleep 5; i=$((i+1))
        done
        if [ "$BACK" = true ]; then
            pass "节点重启回池，done 副本恢复至 2（旧副本复用）"
        else
            fail "节点回池或副本恢复失败"
        fi

        # 1e. 回池后新写入成功
        echo "post-rejoin-$(date +%s)" > /tmp/atoll-post.txt
        if atoll put -replicas 2 -f /tmp/atoll-post.txt "${TEST_DIR}/keep.txt" >/dev/null 2>&1; then
            pass "回池后新写入成功"
        else
            fail "回池后写入失败"
        fi
    fi
fi

# ---- 2. 孤儿对象 GC（闭环：放置 → dry-run 报告 → execute 删除 → 验证消失）----
echo ""
echo "==== 2. 孤儿对象 GC ===="
GC_NODE=$(node_addrs "$(curl -sf "${MASTER}/meta?path=${TEST_DIR}/keep.txt")" | awk '{print $1}')
if [ -n "$GC_NODE" ]; then
    # 直连节点 PUT 假对象（inode 不在元数据中 = 孤儿）
    if curl -sf --connect-timeout 5 -X PUT "http://${GC_NODE}:9421/objects/${FAKE_INODE}" \
        --data-binary "orphan-data" >/dev/null 2>&1; then
        pass "已放置假孤儿 inode=${FAKE_INODE} 于 $GC_NODE"
        sleep 2

        R=$(curl -sf -X POST "${MASTER}/admin/gc" -H "Content-Type: application/json" -d '{"execute": false}')
        if echo "$R" | python3 -c "
import sys, json
d = json.load(sys.stdin)
sys.exit(0 if any(o['id'] == $FAKE_INODE for r in d for o in (r.get('orphans') or [])) else 1)" 2>/dev/null; then
            pass "GC dry-run 报告了假孤儿"
        else
            fail "GC dry-run 未报告假孤儿"
        fi

        curl -sf -X POST "${MASTER}/admin/gc" -H "Content-Type: application/json" \
            -d '{"execute": true}' >/dev/null 2>&1
        sleep 2
        if curl -sf --connect-timeout 3 "http://${GC_NODE}:9421/objects/${FAKE_INODE}" >/dev/null 2>&1; then
            fail "GC execute 后孤儿对象仍可读（未删除）"
        else
            pass "GC execute 删除了孤儿对象"
        fi

        # 正常文件不受影响：内容一致
        if atoll get "${TEST_DIR}/keep.txt" /tmp/atoll-fault-got2.txt 2>/dev/null \
            && cmp -s /tmp/atoll-post.txt /tmp/atoll-fault-got2.txt; then
            pass "GC 后正常文件不受影响（内容一致）"
        else
            fail "GC 后正常文件受影响"
        fi
    else
        fail "放置假孤儿失败（节点 $GC_NODE 不可达）"
    fi
else
    fail "无法确定 GC 测试节点"
fi

# ---- 3. 全程 master 不重启 ----
echo ""
echo "==== 3. master 稳定性 ===="
if curl -sf "${MASTER}/healthz" >/dev/null; then
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
