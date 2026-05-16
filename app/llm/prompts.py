"""Prompt builders for LLM analysis.

Shared between full-log analysis and single-anomaly analysis.
Hardware taxonomy, severity classification, and report formatting live here.
"""
from datetime import datetime
from typing import Any, Optional


def _fmt_ts(ts: Any) -> str:
    """Safely format a timestamp (datetime object or ISO string) to Y-m-d H:M:S."""
    if ts is None:
        return "N/A"
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(ts, str) and ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return ts[:19] if len(ts) >= 19 else ts
    return str(ts)


# -----------------------------------------------------------------------------
# Hardware taxonomy
# -----------------------------------------------------------------------------


def _detect_hw_type(msg: str) -> Optional[str]:
    """Return hardware category given a log message, or None."""
    if not msg:
        return None
    HW_KW = {
        'mb': ['sensor', 'thermal', 'overheat', 'fan', 'voltage', 'psu',
               'chassis', 'bios', 'boot', 'intrusion', 'sel ',
               'system event', 'power on', 'power off', 'reset'],
        'cpu': ['cpu', 'core', 'processor', 'core_temp', 'package_temp',
                'processor', 'p-state', 'c-state'],
        'mem': ['mem', 'memory', 'dram', 'ecc', 'ram', 'corrected', 'uncorrectable'],
        'disk': ['disk', 'nvme', 'ssd', 'hdd', 'sata', 'pcie', 'block',
                 'media', 'media error', 'pcie error', 'drive', 'hdd fault'],
        'raid': ['raid', 'lsi', 'megaraid', 'perc', 'hba', '阵列',
                 'logical drive', 'physical drive', 'vd ', 'pd ', 'bbu',
                 'rebuild', 'patrol', 'consistency'],
        'net': ['eth', 'nic', 'network', 'ethernet', 'port', 'link',
                'tcp', 'udp', 'mac', 'arp', 'lldp', 'mlag', 'bond'],
        'npu': ['npu', 'ascend', 'hiai', 'dvpp', 'aicore', 'aicpu',
                'devicecore', 'npu_ex', 'npuinfo', 'npusched', 'ai_core',
                'ai_cpu', 'cann', 'him_config', 'hicama', 'hdc'],
        'bmc': ['ipmi', 'sel', 'sensor', 'fru', 'sdr', 'pef', 'bmc watch',
                'watchdog', 'webui', 'kvm', 'vmm', 'firmware', 'bmc'],
        'agent': ['agentless', 'hardware', 'signature', 'maintenance',
                  'diag', 'diagnosis', 'ism', 'ibmc', 'imanager'],
    }
    lower = msg.lower()
    for hw, kws in HW_KW.items():
        for kw in kws:
            if kw in lower:
                return hw
    return None


def _entry_level(e: Any) -> str:
    """Return ERROR/WARNING/INFO based on raw message content."""
    ERR_KW = ['fail', 'error', 'critical', 'fault', 'lost', 'miss', 'timeout',
              'abort', 'unable', 'incorrect', 'critical', 'emergency', 'alert']
    WARN_KW = ['warn', 'notice', 'info recovery', 'degraded']
    raw = ((getattr(e, 'message', None) or '') + ' ' + (getattr(e, 'module', None) or '')).lower()
    if any(k in raw for k in ERR_KW):
        return 'ERROR'
    if any(k in raw for k in WARN_KW):
        return 'WARNING'
    lvl = (getattr(e, 'level', None) or '').upper()
    if 'ERR' in lvl or 'CRIT' in lvl or 'FAIL' in lvl:
        return 'ERROR'
    if 'WARN' in lvl:
        return 'WARNING'
    return 'INFO'


# -----------------------------------------------------------------------------
# Prompt builders
# -----------------------------------------------------------------------------


def build_prompt(req: Any) -> str:
    """Build full-log analysis prompt from an LLMAnalysisRequest."""
    lines = ["# BMC 日志异常分析报告", ""]

    # ── Hardware summary ───────────────────────────────────────────────────
    hw_labels = {
        'mb': '主板/传感器', 'cpu': 'CPU', 'mem': '内存',
        'disk': '硬盘/NVMe', 'raid': 'RAID/存储', 'net': '网卡/网络',
        'npu': 'NPU/昇腾', 'bmc': 'BMC/iBMC', 'agent': 'Agentless',
    }
    HW_KW_KEYS = list(hw_labels.keys())
    hw_counts = {k: 0 for k in HW_KW_KEYS}
    hw_entries = {k: [] for k in HW_KW_KEYS}
    top_entries = getattr(req, 'top_entries', None) or []
    for e in top_entries:
        msg = (getattr(e, 'message', None) or '') + ' ' + (getattr(e, 'module', None) or '')
        ht = _detect_hw_type(msg)
        if ht:
            hw_counts[ht] += 1
            if len(hw_entries[ht]) < 2:
                hw_entries[ht].append(e)

    hw_total = sum(hw_counts.values())
    if hw_total > 0:
        lines.append("## 硬件相关事件概览")
        for hw, cnt in sorted(hw_counts.items(), key=lambda x: -x[1]):
            if cnt > 0:
                lines.append(f"- **{hw_labels[hw]}**：{cnt} 条")
                for e in hw_entries[hw][:2]:
                    ts = _fmt_ts(getattr(e, 'timestamp', None))
                    lvl = _entry_level(e)
                    mod = getattr(e, 'module', None) or ''
                    msg = getattr(e, 'message', None) or ''
                    lines.append(f"  - `[{lvl}]` [{ts}] [{mod}] {msg[:100]}")
        lines.append("")

    # ── Anomaly patterns ──────────────────────────────────────────────────
    anomalies = getattr(req, 'anomalies', None) or []
    if anomalies:
        lines.append("## 检测到的异常模式")
        for a in anomalies[:10]:
            desc = getattr(a, 'rule_description', '') or ''
            sev = getattr(a, 'severity', '') or ''
            cnt = getattr(a, 'count', 0) or 0
            first = getattr(a, 'first_seen', None)
            last = getattr(a, 'last_seen', None)
            a_entries = getattr(a, 'entries', None) or []
            lines.append(f"### [{sev}] {desc}")
            lines.append(f"- 出现次数：{cnt}")
            if first:
                lines.append(f"- 首次发生：{first}")
            if last:
                lines.append(f"- 最后发生：{last}")
            lines.append("- 示例日志：")
            for e in a_entries[:3]:
                ts = _fmt_ts(getattr(e, 'timestamp', None))
                lvl = _entry_level(e)
                mod = getattr(e, 'module', None) or ''
                msg = getattr(e, 'message', None) or ''
                lines.append(f"  - `[{lvl}]` [{ts}] [{mod}] {msg}")
            lines.append("")

    # ── Statistical anomalies ──────────────────────────────────────────────
    stat_anomalies = getattr(req, 'statistical_anomalies', None) or []
    if stat_anomalies:
        lines.append("## 统计异常")
        for a in stat_anomalies[:5]:
            desc = getattr(a, 'description', '') or ''
            ws = getattr(a, 'window_start', '') or ''
            we = getattr(a, 'window_end', '') or ''
            lines.append(f"- **{desc}**")
            lines.append(f"  时间窗口：{ws} ~ {we}")
            lines.append("")

    # ── Raw ERROR log ──────────────────────────────────────────────────────
    if top_entries:
        err_entries = [e for e in top_entries if _entry_level(e) == 'ERROR']
        if err_entries:
            lines.append(f"## ERROR 日志（共 {len(err_entries)} 条，取前 20）")
            for e in err_entries[:20]:
                ts = _fmt_ts(getattr(e, 'timestamp', None))
                mod = getattr(e, 'module', None) or ''
                msg = getattr(e, 'message', None) or ''
                lines.append(f"[{ts}] [{mod}] {msg}")
            lines.append("")

    lines.append("""---
【重要指令】请根据以上日志中的**硬件底层故障特征**，而不是上层管理接口（如 PowerMgnt/API）的异常，分析以下三点。

**1. 根因判断（需要更加具体）**
*   **故障部件**：请明确判断是 物理硬盘(HDD/SSD)、RAID卡、背板(Backplane) 还是 SAS/PCIe 链路。
*   **故障位置**：请**务必提取具体的故障槽位号（如 SlotId=4）、Enclosure ID、物理驱动器编号、或 PCIe 地址**。如果无法识别准确位置，请指出推测的故障域。
*   **错误码/关键日志**：提取核心错误码（如 GetPDInfo failed 0x1001）或 S.M.A.R.T 错误详情。请忽略 `[PowerMgnt]`、`[portal]` 等管理层面的 pull 数据错误，因为它们可能是定期轮询的超时，而非物理故障本源。

**2. 优先级建议（业务导向，而非仅看温度/电源）**
*   请基于**对业务连续性和数据安全的影响**来划分优先级。
*   **P0/P1（最高优先）**：涉及数据丢失风险、盘阵降级、硬盘即将离线、业务读写中断、核心部件掉电。
*   **P2（中优先）**：风扇转速过高，温度超过阈值、硬盘预警但未完全掉线、RAID 组成员降级。
*   **P3（低优先）**：日志报错但业务无感、传感器轻微偏移、BMC 自身管理接口报错。
*   **特别说明**：硬盘故障/RAID 成员失效的优先级**不应低于**风扇或电源模块异常。

**3. 解决步骤（给出可执行的命令行与工单建议）**
请按以下结构编写操作指南，包含**诊断命令 + 物理操作 + 兜底方案**：
*   **命令级诊断**：给出具体的排查命令，例如 `storcli64 /c0 /eall /sall show` 或对应厂商工具查询故障盘状态。
*   **物理操作**：明确指出具体操作（如"加固背板及 SAS 线缆连接"、或"尝试重新插拔 SlotId=4 的硬盘"）。
*   **系统/固件修复**：如果物理操作无效，建议执行哪些操作（如"更新 RAID 卡固件"或"更换特定 SlotId 的硬盘"）。
*   **兜底方案**：如问题持续导致业务受损，建议联系对应服务器厂商（如华为、超聚变等）提供完整日志进行固件/驱动升级或 RMA 换件。

---
**回答要求（精简调整版）：**
- 中文，专业，语言**明确**。使用 Markdown 加粗关键信息，例如 `**SlotId=4**`。
- 根因判断请**直接定位到具体的 Slot 或 PCIe 位置**，避免笼统描述。
- 解决步骤请参考对应厂商（华为/超聚变等）的现有运维工具与手段。
- 必须**先排除 `PowerMgnt`、`[portal]` 等管理接口偶发超时层面的干扰**，聚焦底层硬件报错。""")

    return "\n".join(lines)


def build_single_prompt(anomaly_type: str, rule_id: str, rule_description: str,
                        severity: str, count: int, entries) -> str:
    """Build prompt for a single anomaly card analysis."""
    ERR_KW = ['fail', 'error', 'critical', 'fault', 'lost', 'miss',
              'timeout', 'abort', 'unable', 'incorrect', 'emergency', 'alert']
    WARN_KW = ['warn', 'notice', 'info recovery', 'degraded']

    def entry_level(e):
        raw = ((_get_entry(e, 'message') or '') + ' ' + (_get_entry(e, 'module') or '')).lower()
        if any(k in raw for k in ERR_KW):
            return 'ERROR'
        if any(k in raw for k in WARN_KW):
            return 'WARNING'
        lvl = (_get_entry(e, 'level') or '').upper()
        if 'ERR' in lvl or 'CRIT' in lvl or 'FAIL' in lvl:
            return 'ERROR'
        if 'WARN' in lvl:
            return 'WARNING'
        return 'INFO'

    def _get_entry(e: Any, field: str, default: Any = None) -> Any:
        if isinstance(e, dict):
            return e.get(field, default)
        return getattr(e, field, default)

    lines = [
        "# 单条异常根因分析",
        "",
        f"## 异常类型：{anomaly_type}",
        f"### [{severity}] {rule_description}",
        f"- 出现次数：{count}",
        "",
        "## 关联日志（采样最多5条）：",
    ]
    for e in (entries[:5] if entries else []):
        ts = _fmt_ts(_get_entry(e, 'timestamp'))
        lvl = entry_level(e)
        lines.append(f"- `[{lvl}]` [{ts}] [{_get_entry(e, 'module')}] {_get_entry(e, 'message')}")
    lines.append("")
    lines.append("""【重要指令】请根据这条异常的**硬件底层故障特征**进行分析。

**1. 根因判断**
*   **故障部件**：判断是物理硬盘、RAID卡、背板还是 SAS/PCIe 链路故障。
*   **故障位置**：提取具体的故障槽位号（如 SlotId=4）、Enclosure ID 或 PCIe 地址。
*   **错误码/关键日志**：提取核心错误码（如 GetPDInfo failed 0x1001）或 S.M.A.R.T 错误。请忽略 `PowerMgnt`、`portal` 等管理接口超时，它们可能是轮询超时而非物理故障本源。

**2. 优先级建议**
*   **P0/P1**：数据丢失风险、盘阵降级、硬盘即将离线、业务中断 → 最高优先
*   **P2**：硬盘预警未掉线、RAID 成员降级 → 中优先
*   **P3**：业务无感的日志报错 → 低优先

**3. 解决步骤**
*   **命令诊断**：`storcli64 /c0 /eall /sall show` 或厂商工具
*   **物理操作**：如"加固背板 SAS 线缆"或"重新插拔 SlotId=X 硬盘"
*   **固件修复**：更新 RAID 卡固件或更换故障硬盘
*   **兜底方案**：联系华为/超聚变厂商进行固件升级或 RMA 换件

**回答要求**：中文回答，使用 Markdown 加粗关键位置（如 `**SlotId=4**`），直接定位到具体槽位，避免笼统描述。""")
    return "\n".join(lines)
