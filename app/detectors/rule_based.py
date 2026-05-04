import re
from collections import defaultdict
from datetime import datetime
from app.schemas import LogEntry, AnomalyDetection, AnomalyRule

# Known BMC error patterns
RULES = [
    # === 网络/连接类 ===
    AnomalyRule(id="ssl_failed", pattern=r"SSL.*failed|Pre-read ssl failed", description="SSL握手失败", severity="ERROR"),
    AnomalyRule(id="socket_fail", pattern=r"socket recv data fail", description="Socket接收失败", severity="ERROR"),
    AnomalyRule(id="video_timeout", pattern=r"video connect time out", description="视频连接超时", severity="ERROR"),
    AnomalyRule(id="websocket_fail", pattern=r"Get websocket key failed", description="WebSocket密钥获取失败", severity="ERROR"),
    AnomalyRule(id="video_closed", pattern=r"video connection has been closed", description="视频连接断开", severity="WARNING"),

    # === 硬件链路类 ===
    AnomalyRule(id="host_lost", pattern=r"host is lost", description="EDMA主机链路丢失", severity="ERROR"),
    AnomalyRule(id="host_registered", pattern=r"host is registered", description="EDMA主机链路恢复", severity="INFO"),
    AnomalyRule(id="link_down", pattern=r"link is down|link down", description="链路Down", severity="ERROR"),
    AnomalyRule(id="link_up", pattern=r"link is up", description="链路恢复", severity="INFO"),

    # === 系统/电源类 ===
    AnomalyRule(id="power_off", pattern=r"system power off", description="系统关机", severity="ERROR"),
    AnomalyRule(id="power_on", pattern=r"system power on", description="系统开机", severity="INFO"),
    AnomalyRule(id="system_restart", pattern=r"System Restart", description="系统重启", severity="WARNING"),
    AnomalyRule(id="psu_fail", pattern=r"PSU.*fail|power supply.*fail|电源.*故障", description="电源模块故障", severity="ERROR"),
    AnomalyRule(id="undervoltage", pattern=r"undervoltage|under-voltage|低电压", description="电压过低", severity="ERROR"),
    AnomalyRule(id="overvoltage", pattern=r"overvoltage|over-voltage|过电压", description="电压过高", severity="ERROR"),

    # === 温度/散热类 ===
    AnomalyRule(id="thermal_trip", pattern=r"thermal trip|thermal shutdown|过热关机", description="热关机（Thermal Trip）", severity="ERROR"),
    AnomalyRule(id="temp_high", pattern=r"temperature.*high|over temperature|温度.*过高|critical.*temp", description="温度过高", severity="ERROR"),
    AnomalyRule(id="temp_warning", pattern=r"temperature.*warn|high.*temperature|温度警告", description="温度预警", severity="WARNING"),
    AnomalyRule(id="fan_fail", pattern=r"fan.*fail|fan.*absent|fan.*missing|风扇.*故障|风扇.*丢失", description="风扇故障", severity="ERROR"),
    AnomalyRule(id="fan_slow", pattern=r"fan.*slow|fan.*below.*min|fan speed low|风扇.*转速低", description="风扇转速过低", severity="WARNING"),

    # === RAID/存储类 ===
    AnomalyRule(id="raid_fail", pattern=r"RAID.*fail|array.*fail|logical.*fail", description="RAID阵列故障", severity="ERROR"),
    AnomalyRule(id="raid_degraded", pattern=r"raid.*degraded|degraded.*array|logical.*degraded", description="RAID降级", severity="ERROR"),
    AnomalyRule(id="raid_consistency", pattern=r"Consistency Check found inconsistent|Consistency Check.*error", description="RAID一致性检查异常", severity="ERROR"),
    AnomalyRule(id="pdisk_fail", pattern=r"physical.*disk.*fail|pdisk.*fail|drive.*fail|硬盘.*故障|磁盘.*故障", description="物理磁盘故障", severity="ERROR"),
    AnomalyRule(id="pdisk_absent", pattern=r"physical.*disk.*absent|pdisk.*absent|drive.*absent|drive.*missing|硬盘.*丢失", description="硬盘缺失", severity="ERROR"),
    AnomalyRule(id="pdisk_predictive", pattern=r"predictive.*fail|SMART.*fail|drive.*predictive|硬盘.*预测性故障", description="硬盘预测性故障", severity="ERROR"),
    AnomalyRule(id="bbu_fail", pattern=r"BBU.*fail|battery.*fail|电池.*故障", description="BBU/电池故障", severity="ERROR"),
    AnomalyRule(id="bbu_relearn", pattern=r"BBU relearn|BBU.*learning", description="BBU电池重新学习", severity="WARNING"),
    AnomalyRule(id="cache_fail", pattern=r"cache.*fail|write cache.*fail|cached.*data.*lost", description="缓存故障/数据丢失风险", severity="ERROR"),
    AnomalyRule(id="patrol_read", pattern=r"Patrol Read.*error|patrol.*error", description="Patrol Read发现错误", severity="WARNING"),
    AnomalyRule(id="rebuild_fail", pattern=r"rebuild.*fail|reconstruct.*fail|raid.*rebuild.*fail", description="RAID重建失败", severity="ERROR"),
    AnomalyRule(id="rebuild_start", pattern=r"rebuild.*start|reconstruct.*start", description="RAID重建开始", severity="WARNING"),

    # === 内存/CPU类 ===
    AnomalyRule(id="mem_ecc", pattern=r"memory.*error|ECC.*error|mem.*correctable|memory.*corrected", description="内存ECC错误（可纠正）", severity="WARNING"),
    AnomalyRule(id="mem_uncorrectable", pattern=r"uncorrectable.*error|memory.*fatal|内存.*不可纠正", description="内存不可纠正错误", severity="ERROR"),
    AnomalyRule(id="cpu_error", pattern=r"CPU.*error|cpu.*thermal|cpu.*fail", description="CPU错误", severity="ERROR"),

    # === NPU/昇腾类 ===
    AnomalyRule(id="npu_fault", pattern=r"npu.*fault|npu.*fail|npu.*error|devicecore.*error|aicore.*error", description="NPU昇腾设备故障", severity="ERROR"),
    AnomalyRule(id="npu_predictive", pattern=r"npu.*predictive|npu.*degraded|devicecore.*degraded", description="NPU昇腾预测性故障", severity="WARNING"),
    AnomalyRule(id="npu_offline", pattern=r"npu.*offline|npu.*lost|npu.*absent|npu.*remove", description="NPU昇腾掉卡", severity="ERROR"),
    AnomalyRule(id="npu_health", pattern=r"npu.*health|npu.*thermal|npu.*temp|npu.*overheat|npu.*die", description="NPU昇腾温度/健康异常", severity="ERROR"),
    AnomalyRule(id="npu_hbm_error", pattern=r"hbm.*error|hbm.*fail|npu.*hbm|memory.*hbm|npu.*bandwidth", description="NPU HBM内存错误", severity="ERROR"),
    AnomalyRule(id="cann_error", pattern=r"cann.*error|aicpu.*error|dvpp.*error", description="CANN运行时错误", severity="ERROR"),
    AnomalyRule(id="cann_version", pattern=r"cann.*version|aicpu.*version|ascend.*driver", description="CANN/驱动版本事件", severity="INFO"),
    AnomalyRule(id="hiai_fault", pattern=r"hiai.*error|ascend.*error|npu_sched.*fail|npuinfo.*error", description="昇腾海思子系统故障", severity="ERROR"),
    AnomalyRule(id="xpu_error", pattern=r"xpu.*error|xpu.*fault|xpulink.*fail|xpumgr.*error", description="XPU通用错误（华为加速卡）", severity="ERROR"),

    # === GPU/显卡类 ===
    AnomalyRule(id="gpu_fault", pattern=r"gpu.*fault|gpu.*fail|gpu.*error|nvidia.*error|geforce.*error", description="GPU显卡故障", severity="ERROR"),
    AnomalyRule(id="gpu_offline", pattern=r"gpu.*offline|gpu.*lost|gpu.*remove|gpu.*absent|gpu.*missing", description="GPU掉卡", severity="ERROR"),
    AnomalyRule(id="gpu_thermal", pattern=r"gpu.*thermal|gpu.*overheat|gpu.*temp|gpu.*hot|nvidia.*thermal", description="GPU温度过高", severity="ERROR"),
    AnomalyRule(id="gpu_predictive", pattern=r"gpu.*predictive|gpu.*degraded|nvsm.*degraded", description="GPU预测性故障", severity="WARNING"),
    AnomalyRule(id="gpu_memory", pattern=r"gpu.*memory.*error|gpu.*ecc|gpu.*correctable|gpu.*uncorrectable", description="GPU显存错误", severity="ERROR"),
    AnomalyRule(id="nvlink_error", pattern=r"nvlink.*error|nvlink.*fail|NVLink.*error", description="NVLink通信错误", severity="ERROR"),
    AnomalyRule(id="nvsm_error", pattern=r"nvsm.*error|nvsm.*fail|NVSM.*error|NVSMI.*error", description="NVSM管理接口错误", severity="WARNING"),
    AnomalyRule(id="dcgm_error", pattern=r"dcgm.*error|dcgm.*fail|DCGM.*error|GPU.*health.*fail", description="DCGM监控代理错误", severity="ERROR"),

    # === BMC/服务类 ===
    AnomalyRule(id="redfish_fail", pattern=r"get data fail|empty file", description="Redfish数据读取失败", severity="ERROR"),
    AnomalyRule(id="fdm_init", pattern=r"FDM process was initialized", description="FDM进程初始化", severity="INFO"),
    AnomalyRule(id="auth_fail", pattern=r"authentication.*fail|login.*fail|invalid.*user|认证.*失败", description="认证失败", severity="WARNING"),

    # === 通用关键词兜底（无具体规则时） ===
    # 注意：通用规则放最后，count作为补充指标，不单独展示
]

def detect_rule_anomalies(entries: list[LogEntry]) -> list[AnomalyDetection]:
    results = []
    matched = defaultdict(list)

    for entry in entries:
        for rule in RULES:
            if re.search(rule.pattern, entry.message, re.IGNORECASE):
                if rule.module is None or entry.module == rule.module:
                    matched[rule.id].append(entry)

    for rule_id, rule_entries in matched.items():
        rule = next(r for r in RULES if r.id == rule_id)
        # Skip informational events that are too common
        if rule.severity == "INFO" and len(rule_entries) > 100:
            continue
        # Skip single "registered" after "lost" — it's recovery, not anomaly
        if rule.id == "host_registered":
            continue

        timestamps = [e.timestamp for e in rule_entries if e.timestamp]
        results.append(AnomalyDetection(
            rule_id=rule.id,
            rule_description=rule.description,
            severity=rule.severity,
            count=sum(e.repeat_count for e in rule_entries),
            entries=rule_entries[:20],  # Keep max 20 samples
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))

    # Sort by severity then count
    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    results.sort(key=lambda x: (severity_order.get(x.severity, 2), -x.count))
    return results
