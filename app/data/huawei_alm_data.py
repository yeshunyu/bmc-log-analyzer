"""Huawei iBMC ALM alarm code data and decoder.

This module contains pure data (no external dependencies):
  - SUBSYSTEM: subsystem byte → human name
  - SEVERITY_NN: severity nibble → (zh, level)
  - ALARM_DB: alarm code → (description, severity)
  - AlarmCodeInfo: decoded alarm metadata
  - decode_alm(code) → AlarmCodeInfo | None
  - extract_alm_codes(text) → list[AlarmCodeInfo]
  - is_alm_code(text) → bool

Coverage: FusionServer Pro 2288H V5 iBMC告警处理 + Atlas 800T A2 告警处理
Source: EDOC1000054719 (v52, 2025-10-30) + EDOC1100317321 (v07, 2026-04-24)
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Subsystem byte → human name
# ---------------------------------------------------------------------------

SUBSYSTEM: dict[str, str] = {
    "01": "Memory",
    "02": "Voltage",
    "03": "Current",
    "04": "Fan",
    "05": "Physical Security",
    "06": "RAID Card",
    "07": "Processor",
    "08": "PCIe Card",
    "09": "Power Supply",
    "0A": "Cooling Device",
    "0B": "Memory",
    "0C": "Drive Bay",
    "0D": "POST Memory Resize",
    "0E": "System Firmware",
    "0F": "Event Logging Disabled",
    "10": "Mainboard",
    "12": "Chassis",
    "13": "Button",
    "14": "Module/Board",
    "15": "Microcontroller",
    "16": "Add-in Card",
    "17": "Chassis",
    "18": "Chip Set",
    "19": "Other FRU",
    "1A": "BMC",
    "1B": "Management Subsystem",
    "1C": "Battery",
    "1D": "Operating System",
    "1E": "Power Rail",
    "1F": "Version Change",
    "20": "Boot",
    "21": "Boot Error",
    "23": "OS Boot",
    "24": "OS Critical Stop",
    "25": "Slot/Connector",
    "26": "System ACPI",
    "27": "Watchdog2",
    "28": "Platform Alert",
    "29": "Port",
    "2A": "Monitor ASIC",
    "2B": "LAN",
    "2C": "System",
    "2D": "Processor",
    "2E": "Power Supply",
    "2F": "Power Unit",
    "30": "Cooling Device",
    "31": "Memory",
    "32": "Drive Bay",
    "33": "System Firmware",
    "34": "Watchdog1",
    "35": "System Event",
    "36": "Critical Interrupt",
    "37": "Button",
    "38": "Module/Board",
    "39": "Microcontroller",
    "3A": "Add-in Card",
    "3B": "Chassis",
    "3C": "Chip Set",
    "3D": "Other FRU",
    "3E": "PCIe Switch",
    "3F": "Display",
    "40": "Disk",
    "41": "Disk Array",
    "42": "风扇",
    "43": "OS Graceful Stop",
    "44": "Module/Board",
    "45": "风扇",
    "46": "CPU",
    "47": "Power Unit",
    "48": "风扇",
    "49": "DC Voltage",
    "4A": "Current",
    "4B": "Current",
    "4C": "OS",
    "4D": "Power Cap",
    "4E": "Performance",
    "50": "Firmware",
    "51": "Version Change",
    "53": "Base OS Boot",
    "54": "Base OS",
    "55": "OS",
    "57": "IPMB",
    "58": "Mailbox",
    "59": "Bridge",
    "5A": "Management Subsystem",
    "5B": "Battery",
    "5C": "Management Subsystem",
    "5D": "Boot",
    "5E": "Boot",
    "5F": "Base OS",
    "60": "Watchdog",
    "61": "Platform Alert",
    "62": "Sensor",
    "63": "Battery",
    "64": "Global Election",
    "65": "TPM",
    "66": "Storage",
    "67": "PCI",
    "68": "Health Event",
    "69": "Run-Time HA",
    "6A": "SEL Device",
    "6B": "BIOS/Startup",
    "6C": "GPU",
    "6D": "NVMe",
}

# ---------------------------------------------------------------------------
# Severity: last digit of alarm code byte 4 (0=critical, 1=major, 2=minor, 3=info)
# ---------------------------------------------------------------------------

SEVERITY_NN: dict[int, tuple[str, str]] = {
    0: ("紧急", "CRITICAL"),   # 紧急告警 → ERROR
    1: ("严重", "MAJOR"),       # 严重告警 → ERROR
    2: ("轻微", "MINOR"),      # 轻微告警 → WARNING
    3: ("提示", "INFO"),       # 提示告警 → INFO
}

# ---------------------------------------------------------------------------
# Alarm code database
# ---------------------------------------------------------------------------

ALARM_DB: dict[str, tuple[str, str]] = {
    # ===== Memory (0x01) =====
    "ALM-0x01000001": ("CPU下挂内存PPR失败", "CRITICAL"),
    "ALM-0x01000003": ("CPU温度过高即将触发降频", "MAJOR"),
    "ALM-0x01000005": ("内存初始化错误", "CRITICAL"),
    "ALM-0x01000007": ("内存PPR失败", "MAJOR"),
    "ALM-0x01000009": ("内存Training失败", "MAJOR"),
    "ALM-0x0100000B": ("内存配置错误", "CRITICAL"),
    "ALM-0x0100000D": ("内存Temperature Error", "MAJOR"),
    "ALM-0x0100000F": ("内存Smarterror", "MINOR"),
    "ALM-0x01000011": ("内存IERR", "CRITICAL"),
    "ALM-0x01000013": ("内存温度过高", "MINOR"),
    "ALM-0x01000015": ("内存SBE事件", "MINOR"),
    "ALM-0x01000017": ("内存DBE事件", "CRITICAL"),
    "ALM-0x01000019": ("CPU下挂内存VDDQ电压读取失败", "MINOR"),
    "ALM-0x0100001B": ("CPU下挂内存VDDQ1电压读取失败", "MINOR"),
    "ALM-0x0100001D": ("CPU下挂内存VDDQ2电压读取失败", "MINOR"),
    "ALM-0x0100001F": ("CPU下挂内存VDDQ1电压读取失败", "MINOR"),
    "ALM-0x01000021": ("CPU下挂内存VDDQ2电压读取失败", "MINOR"),
    "ALM-0x01000023": ("PMem温度过高", "MINOR"),
    "ALM-0x01000025": ("PMem温度读取失败", "MINOR"),
    "ALM-0x01000027": ("PMem内存过热导致系统下电", "CRITICAL"),
    "ALM-0x01000029": ("PMem轻微故障", "MINOR"),
    "ALM-0x0100002B": ("PMem严重故障", "CRITICAL"),
    "ALM-0x0100002D": ("CPU下挂内存PPR成功", "INFO"),
    "ALM-0x0100003B": ("内存温度过高", "MINOR"),
    "ALM-0x01000061": ("PMem温度过高", "MINOR"),
    "ALM-0x01000063": ("PMem温度读取失败", "MINOR"),
    "ALM-0x01000065": ("PMem轻微故障", "MINOR"),
    "ALM-0x01000067": ("PMem严重故障", "CRITICAL"),
    "ALM-0x01000069": ("PMem内存过热导致系统下电", "CRITICAL"),

    # ===== Mainboard / System (0x10, 0x2C) =====
    "ALM-0x10000001": ("主板启动正常", "INFO"),
    "ALM-0x10000003": ("主板过热", "MAJOR"),
    "ALM-0x10000005": ("主板PFA告警", "MINOR"),
    "ALM-0x10000007": ("主板ESD告警", "MINOR"),
    "ALM-0x10000009": ("主板FRU读取失败", "MINOR"),
    "ALM-0x1000000B": ("主板POST错误", "MAJOR"),
    "ALM-0x1000000D": ("主板RTC电池电压低", "MAJOR"),
    "ALM-0x1000000F": ("主板NMI事件", "CRITICAL"),
    "ALM-0x10000011": ("主板SMI事件", "MAJOR"),
    "ALM-0x10000013": ("主板PCIE发热告警", "MINOR"),
    "ALM-0x10000015": ("主板热插拔硬盘背板通信中断", "MINOR"),
    "ALM-0x10000017": ("主板VBUS告警", "MINOR"),
    "ALM-0x10000019": ("主板电源架构模式变更", "INFO"),
    "ALM-0x1000001B": ("主板CPLD版本不匹配", "MINOR"),
    "ALM-0x1000001D": ("主板Mezz扣卡温度过高", "MAJOR"),
    "ALM-0x10000021": ("主板加速卡扣卡温度过高", "MAJOR"),
    "ALM-0x10000023": ("主板TPM绑定失败", "MINOR"),
    "ALM-0x10000025": ("主板内存镜像模式变更", "INFO"),
    "ALM-0x10000027": ("主板内存热备模式变更", "INFO"),
    "ALM-0x10000029": ("主板内存跨槽位迁移模式变更", "INFO"),
    "ALM-0x1000002B": ("缓起电路电压过高", "MAJOR"),
    "ALM-0x1000002D": ("缓起电路电压过低", "MAJOR"),
    "ALM-0x1000002F": ("主板电源模块型号不匹配", "MINOR"),
    "ALM-0x10000031": ("主板电源模块功率有限", "MINOR"),
    "ALM-0x10000033": ("主板电源模块功率有限", "MINOR"),
    "ALM-0x10000035": ("主板电源模块过载", "MAJOR"),
    "ALM-0x10000037": ("主板电源模块功率有限", "MINOR"),
    "ALM-0x10000039": ("主板电源模块功率有限", "MINOR"),
    "ALM-0x1000003B": ("主板CFFH冗余电源模块故障", "MAJOR"),
    "ALM-0x1000003D": ("主板电源模块协议异常", "MAJOR"),
    "ALM-0x1000003F": ("主板电源模块功率受限", "MINOR"),
    "ALM-0x10000041": ("主板系统最大功率受限", "MINOR"),
    "ALM-0x10000043": ("主板NMI事件", "CRITICAL"),
    "ALM-0x10000045": ("主板内存配置变更", "INFO"),
    "ALM-0x10000047": ("主板TPM离线", "MINOR"),
    "ALM-0x10000049": ("TPM绑定成功", "INFO"),
    "ALM-0x1000004B": ("TPM绑定失败", "MINOR"),
    "ALM-0x100000A5": ("缓起电路电压过高", "MAJOR"),
    "ALM-0x100000A7": ("缓起电路电压过低", "MAJOR"),
    "ALM-0x100000B7": ("缓起电路电压过低", "MAJOR"),
    "ALM-0x100000B9": ("缓起电路电压过高", "MAJOR"),

    # ===== System (0x2C) =====
    "ALM-0x2C000001": ("系统严重告警", "CRITICAL"),
    "ALM-0x2C000003": ("系统异常下电", "CRITICAL"),
    "ALM-0x2C000005": ("系统下电", "MAJOR"),
    "ALM-0x2C000007": ("系统异常下电", "CRITICAL"),
    "ALM-0x2C000009": ("系统重启", "MAJOR"),
    "ALM-0x2C00000B": ("系统电源异常", "CRITICAL"),
    "ALM-0x2C00000D": ("系统电源正常", "INFO"),
    "ALM-0x2C00000F": ("系统过热", "CRITICAL"),
    "ALM-0x2C000011": ("系统温度恢复正常", "INFO"),
    "ALM-0x2C000013": ("系统自检失败", "CRITICAL"),
    "ALM-0x2C000015": ("系统启动失败", "CRITICAL"),
    "ALM-0x2C000017": ("系统运行中", "INFO"),
    "ALM-0x2C000019": ("BMC复位", "INFO"),
    "ALM-0x2C00001B": ("BMC Watchdog重启", "MAJOR"),
    "ALM-0x2C00001D": ("BIOS Watchdog重启", "MAJOR"),
    "ALM-0x2C00001F": ("系统电源开启", "INFO"),
    "ALM-0x2C000021": ("系统电源关闭", "INFO"),
    "ALM-0x2C000023": ("上电失败", "CRITICAL"),
    "ALM-0x2C000025": ("系统上电超时", "CRITICAL"),
    "ALM-0x2C000027": ("电源模块缺失", "CRITICAL"),
    "ALM-0x2C000029": ("电源模块故障", "CRITICAL"),
    "ALM-0x2C00002B": ("上电超时", "CRITICAL"),
    "ALM-0x2C00002D": ("电源模块温度过高", "MAJOR"),
    "ALM-0x2C00002F": ("电源模块故障恢复", "INFO"),
    "ALM-0x2C000031": ("电源模块通信失败", "MAJOR"),
    "ALM-0x2C000033": ("电源模块校准失败", "MAJOR"),
    "ALM-0x2C000035": ("电源模块风扇故障", "MAJOR"),
    "ALM-0x2C000037": ("电源模块输入故障", "MAJOR"),
    "ALM-0x2C000039": ("电源模块输出故障", "MAJOR"),
    "ALM-0x2C00003B": ("电源模块过载告警", "MAJOR"),
    "ALM-0x2C00003D": ("电源模块过压告警", "MAJOR"),
    "ALM-0x2C00003F": ("电源模块欠压告警", "MAJOR"),
    "ALM-0x2C000041": ("电源模块过流告警", "MAJOR"),
    "ALM-0x2C000043": ("电源模块过功率告警", "MAJOR"),
    "ALM-0x2C000045": ("电源模块Predictive Failure", "MINOR"),
    "ALM-0x2C000047": ("电源模块良好状态", "INFO"),
    "ALM-0x2C000049": ("电源模块混合功率状态", "MINOR"),
    "ALM-0x2C00004B": ("内存配置错误", "CRITICAL"),
    "ALM-0x2C00004D": ("CPU配置错误", "CRITICAL"),
    "ALM-0x2C00004F": ("PCIe配置错误", "MAJOR"),
    "ALM-0x2C000051": ("PCIe卡松开", "MINOR"),
    "ALM-0x2C000053": ("PCIe卡拔出", "MINOR"),
    "ALM-0x2C000055": ("PCIe卡不在位", "MINOR"),
    "ALM-0x2C000057": ("BIOS默认配置恢复", "MINOR"),
    "ALM-0x2C000059": ("BIOS配置变更", "MINOR"),
    "ALM-0x2C00005B": ("密码清除跳线变更", "MINOR"),
    "ALM-0x2C00005D": ("密码重置", "MINOR"),
    "ALM-0x2C00005F": ("BIOS启动失败", "MAJOR"),
    "ALM-0x2C000061": ("系统启动超时", "MAJOR"),
    "ALM-0x2C000063": ("系统启动取消", "MINOR"),
    "ALM-0x2C000065": ("启动设备变更", "MINOR"),
    "ALM-0x2C000067": ("启动顺序变更", "MINOR"),
    "ALM-0x2C000069": ("启动设备不存在", "MINOR"),
    "ALM-0x2C00006B": ("启动项恢复", "MINOR"),
    "ALM-0x2C00006D": ("引导介质丢失", "MAJOR"),
    "ALM-0x2C00006F": ("BMC操作系统启动异常", "MAJOR"),
    "ALM-0x2C000071": ("BMC操作系统运行异常", "MAJOR"),
    "ALM-0x2C000073": ("BMC操作系统关闭", "MINOR"),
    "ALM-0x2C000075": ("BMC芯片温度过高", "MAJOR"),
    "ALM-0x2C000077": ("BMC芯片温度恢复正常", "INFO"),
    "ALM-0x2C000079": ("BMC FRU读取失败", "MINOR"),
    "ALM-0x2C00007B": ("BMC时间同步失败", "MINOR"),
    "ALM-0x2C00007D": ("BMC Flash故障", "CRITICAL"),
    "ALM-0x2C00007F": ("PSU电源无效混插", "CRITICAL"),
    "ALM-0x2C000081": ("系统电源供给不稳定", "CRITICAL"),
    "ALM-0x2C000083": ("电源模块Predictive Failure", "MINOR"),
    "ALM-0x2C000085": ("NPU昇腾设备故障", "CRITICAL"),
    "ALM-0x2C000087": ("NPU昇腾设备温度异常", "MAJOR"),
    "ALM-0x2C000089": ("NPU昇腾设备通信异常", "CRITICAL"),
    "ALM-0x2C00008B": ("NPU昇腾设备掉电", "CRITICAL"),
    "ALM-0x2C00008D": ("NPU昇腾设备启动失败", "CRITICAL"),
    "ALM-0x2C00008F": ("NPU昇腾设备HBM错误", "CRITICAL"),
    "ALM-0x2C000091": ("NPU昇腾设备恢复", "INFO"),
    "ALM-0x2C000093": ("CANN驱动错误", "MAJOR"),
    "ALM-0x2C000095": ("CANN运行时错误", "MAJOR"),
    "ALM-0x2C000097": ("昇腾设备故障", "CRITICAL"),
    "ALM-0x2C000099": ("昇腾设备掉卡", "CRITICAL"),
    "ALM-0x2C00009B": ("昇腾设备温度过高", "MAJOR"),
    "ALM-0x2C00009D": ("昇腾设备HBM错误", "CRITICAL"),
    "ALM-0x2C00009F": ("昇腾设备健康状态异常", "MAJOR"),

    # ===== BMC (0x1A) =====
    "ALM-0x1A000001": ("BMC FRU读取成功", "INFO"),
    "ALM-0x1A000003": ("BMC FRU读取失败", "MINOR"),
    "ALM-0x1A000005": ("BMC配置恢复默认", "MINOR"),
    "ALM-0x1A000007": ("BMC固件更新成功", "INFO"),
    "ALM-0x1A000009": ("BMC固件更新失败", "MAJOR"),
    "ALM-0x1A00000B": ("BMC温度正常", "INFO"),
    "ALM-0x1A00000D": ("BMC温度过高", "MAJOR"),
    "ALM-0x1A00000F": ("BMC芯片温度过高", "MAJOR"),
    "ALM-0x1A000011": ("BMC芯片温度恢复正常", "INFO"),
    "ALM-0x1A000013": ("BMC供电故障", "CRITICAL"),
    "ALM-0x1A000015": ("BMC供电正常", "INFO"),
    "ALM-0x1A000017": ("BMC启动正常", "INFO"),
    "ALM-0x1A000019": ("与其他iBMC心跳异常", "MAJOR"),
    "ALM-0x1A00001B": ("BMC重启", "MINOR"),
    "ALM-0x1A00001D": ("BMC Watchdog超时", "MAJOR"),
    "ALM-0x1A00001F": ("BMC内存不足", "MAJOR"),
    "ALM-0x1A000021": ("BMC存储空间不足", "MAJOR"),
    "ALM-0x1A000023": ("BMC网络断开", "MAJOR"),
    "ALM-0x1A000025": ("BMC网络恢复", "INFO"),
    "ALM-0x1A000027": ("BMC认证失败", "MINOR"),
    "ALM-0x1A000029": ("BMC会话超限", "MINOR"),
    "ALM-0x1A00002B": ("BMC用户创建", "INFO"),
    "ALM-0x1A00002D": ("BMC用户删除", "INFO"),
    "ALM-0x1A00002F": ("BMC用户权限变更", "INFO"),
    "ALM-0x1A000031": ("Nand Flash预留块低于阈值", "MAJOR"),
    "ALM-0x1A000033": ("Nand Flash写入量超过门限告警", "MINOR"),
    "ALM-0x1A000035": ("BMC版本变更", "INFO"),
    "ALM-0x1A000037": ("BMC时间同步成功", "INFO"),
    "ALM-0x1A000039": ("BMC温度传感器故障", "MAJOR"),
    "ALM-0x1A00003B": ("BMC健康状态异常", "MAJOR"),
    "ALM-0x1A00003D": ("BMC健康状态恢复", "INFO"),
    "ALM-0x1A00003F": ("BMC与主机通信异常", "MAJOR"),
    "ALM-0x1A000041": ("BMC核心温度过高", "MINOR"),
    "ALM-0x1A000043": ("Nand Flash写入量超过门限告警", "MINOR"),

    # ===== Chassis (0x12) =====
    "ALM-0x12000001": ("机箱盖板打开", "MINOR"),
    "ALM-0x12000003": ("机箱盖板关闭", "INFO"),
    "ALM-0x12000005": ("前面板解锁", "MINOR"),
    "ALM-0x12000007": ("前面板锁定", "INFO"),
    "ALM-0x12000009": ("出风口温度过高", "MINOR"),
    "ALM-0x1200000B": ("出风口温度过高", "MAJOR"),
    "ALM-0x1200000D": ("进风口温度过高", "MINOR"),
    "ALM-0x1200000F": ("进风口温度过高", "MAJOR"),
    "ALM-0x12000011": ("环境温度异常", "MINOR"),
    "ALM-0x12000013": ("机箱入侵", "MINOR"),
    "ALM-0x12000015": ("机箱入侵恢复", "INFO"),
    "ALM-0x12000017": ("右挂耳不在位", "MINOR"),
    "ALM-0x12000019": ("左挂耳不在位", "MINOR"),
    "ALM-0x1200001B": ("右挂耳恢复正常", "INFO"),
    "ALM-0x1200001D": ("左挂耳恢复正常", "INFO"),
    "ALM-0x1200001F": ("右挂耳不在位", "MINOR"),
    "ALM-0x12000021": ("左挂耳不在位", "MINOR"),

    # ===== PCIe Card (0x08) =====
    "ALM-0x08000001": ("PCIe标卡在位", "INFO"),
    "ALM-0x08000003": ("PCIe标卡不在位", "MINOR"),
    "ALM-0x08000005": ("PCIe标卡故障", "MAJOR"),
    "ALM-0x08000007": ("PCIe标卡可恢复故障", "MINOR"),
    "ALM-0x08000009": ("PCIe标卡升温告警", "MINOR"),
    "ALM-0x0800000B": ("PCIe标卡过热", "MAJOR"),
    "ALM-0x0800000D": ("PCIe标卡降温正常", "INFO"),
    "ALM-0x0800000F": ("PCIe标卡电源故障", "MAJOR"),
    "ALM-0x08000011": ("PCIe标卡电源恢复", "INFO"),
    "ALM-0x08000013": ("PCIe标卡启动成功", "INFO"),
    "ALM-0x08000015": ("PCIe标卡启动失败", "MAJOR"),
    "ALM-0x08000017": ("PCIe标卡错误", "MAJOR"),
    "ALM-0x08000019": ("PCIe标卡健康状态异常", "MAJOR"),
    "ALM-0x0800001B": ("PCIe标卡健康状态恢复", "INFO"),
    "ALM-0x0800001D": ("PCIe标卡重新配置", "MINOR"),
    "ALM-0x0800001F": ("PCIe标卡访问超时", "MAJOR"),
    "ALM-0x08000021": ("PCIe标卡访问恢复", "INFO"),
    "ALM-0x08000023": ("PCIe标卡Vital Product Data缺失", "MINOR"),
    "ALM-0x08000025": ("PCIe标卡VPD读取失败", "MINOR"),
    "ALM-0x08000027": ("PCIe标卡设备枚举失败", "CRITICAL"),
    "ALM-0x08000029": ("PCIe标卡控制器初始化失败", "MAJOR"),
    "ALM-0x0800002B": ("PCIe标卡固件版本不匹配", "MINOR"),
    "ALM-0x0800002D": ("PCIe标卡电源耗尽", "MAJOR"),
    "ALM-0x0800002F": ("PCIe标卡电源受限", "MINOR"),
    "ALM-0x08000031": ("PCIe标卡电源恢复正常", "INFO"),
    "ALM-0x08000033": ("PCIe标卡端口Training失败", "MAJOR"),
    "ALM-0x08000035": ("PCIe标卡端口Training成功", "INFO"),
    "ALM-0x08000037": ("PCIe标卡带宽降级", "MINOR"),
    "ALM-0x08000039": ("PCIe标卡带宽恢复正常", "INFO"),
    "ALM-0x0800003B": ("PCIe标卡错误恢复", "INFO"),
    "ALM-0x0800003D": ("PCIe标卡AER错误", "MAJOR"),
    "ALM-0x0800003F": ("PCIe标卡VPD更新成功", "INFO"),
    "ALM-0x08000041": ("PCIe标卡VPD更新失败", "MINOR"),
    "ALM-0x08000043": ("PCIe标卡恢复要求", "MINOR"),
    "ALM-0x08000045": ("PCIe标卡电源过载", "MAJOR"),
    "ALM-0x08000047": ("PCIe标卡Predictive Failure", "MINOR"),
    "ALM-0x08000049": ("PCIe标卡可用性降低", "MINOR"),
    "ALM-0x0800004B": ("PCIe标卡功能降级", "MINOR"),
    "ALM-0x0800004D": ("PCIe标卡版本变更", "MINOR"),
    "ALM-0x0800004F": ("PCIe标卡性能受限", "MINOR"),
    "ALM-0x08000051": ("PCIe标卡访问错误", "MAJOR"),
    "ALM-0x08000053": ("PCIe标卡访问错误恢复", "INFO"),
    "ALM-0x08000055": ("PCIe标卡固件更新中", "MINOR"),
    "ALM-0x08000057": ("PCIe标卡固件更新完成", "INFO"),
    "ALM-0x08000059": ("PCIe标卡固件更新失败", "MAJOR"),
    "ALM-0x0800005B": ("PCIe标卡加电失败", "MAJOR"),
    "ALM-0x0800005D": ("PCIe标卡断开连接", "MINOR"),
    "ALM-0x0800005F": ("PCIe标卡重新连接", "MINOR"),
    "ALM-0x08000061": ("PCIe标卡添加成功", "INFO"),
    "ALM-0x08000063": ("PCIe标卡移除成功", "INFO"),
    "ALM-0x08000065": ("PCIe标卡接口通信异常", "MAJOR"),
    "ALM-0x08000067": ("PCIe标卡设备枚举失败", "CRITICAL"),

    # ===== RAID Card (0x06) =====
    "ALM-0x06000001": ("RAID扣卡正常", "INFO"),
    "ALM-0x06000003": ("RAID扣卡不在位", "MINOR"),
    "ALM-0x06000005": ("RAID扣卡故障", "CRITICAL"),
    "ALM-0x06000007": ("RAID扣卡MCE/AER错误", "CRITICAL"),
    "ALM-0x06000009": ("RAID扣卡初始化失败", "CRITICAL"),
    "ALM-0x0600000B": ("RAID扣卡温度过高", "MAJOR"),
    "ALM-0x0600000D": ("RAID扣卡温度恢复正常", "INFO"),
    "ALM-0x0600000F": ("RAID扣卡电池故障", "MAJOR"),
    "ALM-0x06000011": ("RAID扣卡电池正常", "INFO"),
    "ALM-0x06000013": ("RAID扣卡电池电量低", "MINOR"),
    "ALM-0x06000015": ("RAID扣卡缓存故障", "MAJOR"),
    "ALM-0x06000017": ("RAID扣卡缓存恢复", "INFO"),
    "ALM-0x06000019": ("RAID扣卡固件更新", "MINOR"),
    "ALM-0x0600001B": ("RAID扣卡控制器故障", "CRITICAL"),
    "ALM-0x0600001D": ("RAID扣卡控制器正常", "INFO"),
    "ALM-0x0600001F": ("RAID扣卡启动成功", "INFO"),
    "ALM-0x06000021": ("RAID扣卡启动失败", "MAJOR"),
    "ALM-0x06000023": ("RAID扣卡BBU故障", "MAJOR"),
    "ALM-0x06000025": ("RAID扣卡控制器通信丢失", "CRITICAL"),
    "ALM-0x06000027": ("RAID扣卡控制器初始化异常", "CRITICAL"),
    "ALM-0x06000029": ("RAID扣卡恢复重建", "MINOR"),
    "ALM-0x0600002B": ("RAID扣卡重建失败", "CRITICAL"),
    "ALM-0x0600002D": ("RAID扣卡Patrol Read错误", "MINOR"),
    "ALM-0x0600002F": ("RAID扣卡一致性检查错误", "MINOR"),
    "ALM-0x06000031": ("RAID扣卡预见性故障", "MINOR"),

    # ===== GPU (0x6C) =====
    "ALM-0x6C000001": ("GPU显卡正常", "INFO"),
    "ALM-0x6C000003": ("GPU显卡故障", "CRITICAL"),
    "ALM-0x6C000005": ("GPU显卡不在位", "MINOR"),
    "ALM-0x6C000007": ("GPU显卡温度过高", "MAJOR"),
    "ALM-0x6C000009": ("GPU显卡温度恢复", "INFO"),
    "ALM-0x6C00000B": ("GPU显卡电源故障", "MAJOR"),
    "ALM-0x6C00000D": ("GPU显卡电源恢复", "INFO"),
    "ALM-0x6C00000F": ("GPU显卡电源过载", "MAJOR"),
    "ALM-0x6C000011": ("GPU显卡Predictive Failure", "MINOR"),
    "ALM-0x6C000013": ("GPU显卡LED指示灯点亮", "MINOR"),
    "ALM-0x6C000015": ("GPU显卡LED指示灯熄灭", "INFO"),
    "ALM-0x6C000017": ("GPU显卡访问超时", "MAJOR"),
    "ALM-0x6C000019": ("GPU显卡访问恢复", "INFO"),
    "ALM-0x6C00001B": ("GPU显卡VPD读取失败", "MINOR"),
    "ALM-0x6C00001D": ("GPU显卡VPD更新失败", "MINOR"),
    "ALM-0x6C00001F": ("GPU显卡固件更新失败", "MAJOR"),
    "ALM-0x6C000021": ("GPU NVLink断开", "MAJOR"),
    "ALM-0x6C000023": ("GPU NVLink恢复", "INFO"),
    "ALM-0x6C000025": ("GPU显存错误", "CRITICAL"),
    "ALM-0x6C000027": ("GPU显存错误恢复", "INFO"),
    "ALM-0x6C000029": ("GPU ECC错误", "MINOR"),
    "ALM-0x6C00002B": ("GPU ECC不可纠正错误", "CRITICAL"),

    # ===== NVMe (0x6D) =====
    "ALM-0x6D000001": ("NVMe SSD正常", "INFO"),
    "ALM-0x6D000003": ("NVMe SSD故障", "CRITICAL"),
    "ALM-0x6D000005": ("NVMe SSD不在位", "MINOR"),
    "ALM-0x6D000007": ("NVMe SSD温度过高", "MAJOR"),
    "ALM-0x6D000009": ("NVMe SSD温度恢复", "INFO"),
    "ALM-0x6D00000B": ("NVMe SSD写入量超限", "MINOR"),
    "ALM-0x6D00000D": ("NVMe SSD读取量超限", "MINOR"),
    "ALM-0x6D00000F": ("NVMe SSD可用空间不足", "MINOR"),
    "ALM-0x6D000011": ("NVMe SSD可用空间恢复", "INFO"),
    "ALM-0x6D000013": ("NVMe SSD Predictiv Failure", "MINOR"),
    "ALM-0x6D000015": ("NVMe SSD上电失败", "MAJOR"),
    "ALM-0x6D000017": ("NVMe SSD格式化失败", "MAJOR"),
    "ALM-0x6D000019": ("NVMe SSD热插拔成功", "INFO"),
    "ALM-0x6D00001B": ("NVMe SSD不一致性", "MINOR"),
    "ALM-0x6D00001D": ("NVMe SSD重建完成", "INFO"),

    # ===== Fan (0x04) =====
    "ALM-0x04000001": ("风扇转速过低", "MINOR"),
    "ALM-0x04000003": ("风扇转速恢复正常", "INFO"),
    "ALM-0x04000005": ("风扇缺失", "MINOR"),
    "ALM-0x04000007": ("风扇存在", "INFO"),
    "ALM-0x04000009": ("风扇转速过高", "MINOR"),
    "ALM-0x0400000B": ("风扇转速恢复", "INFO"),
    "ALM-0x0400000D": ("风扇故障", "MAJOR"),
    "ALM-0x0400000F": ("风扇故障恢复", "INFO"),
    "ALM-0x04000011": ("风扇模块故障", "MAJOR"),
    "ALM-0x04000013": ("风扇模块故障恢复", "INFO"),
    "ALM-0x04000015": ("风扇冗余丧失", "CRITICAL"),
    "ALM-0x04000017": ("风扇冗余恢复", "INFO"),

    # ===== Power Supply (0x09) =====
    "ALM-0x09000001": ("电源模块正常", "INFO"),
    "ALM-0x09000003": ("电源模块故障", "CRITICAL"),
    "ALM-0x09000005": ("电源模块缺失", "MINOR"),
    "ALM-0x09000007": ("电源模块存在", "INFO"),
    "ALM-0x09000009": ("电源模块输入异常", "MAJOR"),
    "ALM-0x0900000B": ("电源模块输入正常", "INFO"),
    "ALM-0x0900000D": ("电源模块输出异常", "MAJOR"),
    "ALM-0x0900000F": ("电源模块输出正常", "INFO"),
    "ALM-0x09000011": ("电源模块温度过高", "MAJOR"),
    "ALM-0x09000013": ("电源模块温度正常", "INFO"),
    "ALM-0x09000015": ("电源模块Predictive Failure", "MINOR"),
    "ALM-0x09000017": ("电源模块过载", "MAJOR"),
    "ALM-0x09000019": ("电源模块过压", "MAJOR"),
    "ALM-0x0900001B": ("电源模块欠压", "MAJOR"),
    "ALM-0x0900001D": ("电源模块过流", "MAJOR"),
    "ALM-0x0900001F": ("电源模块功率受限", "MINOR"),
    "ALM-0x09000021": ("电源模块混合功率状态", "MINOR"),
    "ALM-0x09000023": ("电源模块固件更新", "MINOR"),
    "ALM-0x09000025": ("电源模块固件更新失败", "MAJOR"),
    "ALM-0x09000027": ("电源模块校准成功", "INFO"),
    "ALM-0x09000029": ("电源模块校准失败", "MAJOR"),
    "ALM-0x0900002B": ("电源模块通信失败", "MAJOR"),
    "ALM-0x0900002D": ("电源模块通信恢复", "INFO"),

    # ===== Port / Network (0x29) =====
    "ALM-0x29000001": ("网口光模块在位", "INFO"),
    "ALM-0x29000003": ("网口光模块不在位", "MINOR"),
    "ALM-0x29000005": ("网口光模块故障", "MAJOR"),
    "ALM-0x29000007": ("网口光模块温度过高", "MAJOR"),
    "ALM-0x29000009": ("网口光模块温度恢复", "INFO"),
    "ALM-0x2900000B": ("网口光模块功率异常", "CRITICAL"),
    "ALM-0x2900000D": ("网口光模块功率恢复正常", "INFO"),
    "ALM-0x2900000F": ("网口光模块发射器故障", "MAJOR"),
    "ALM-0x29000011": ("网口光模块接收器故障", "MAJOR"),
    "ALM-0x29000013": ("网口光模块VPD读取失败", "MINOR"),
    "ALM-0x29000015": ("网口光模块型号不匹配", "MINOR"),
    "ALM-0x29000017": ("网卡光模块的功率异常", "CRITICAL"),
    "ALM-0x29000019": ("网口链路断开", "MINOR"),
    "ALM-0x2900001B": ("网口链路恢复", "INFO"),
    "ALM-0x2900001D": ("网口速率降级", "MINOR"),
    "ALM-0x2900001F": ("网口速率恢复正常", "INFO"),

    # ===== Voltage (0x02) =====
    "ALM-0x02000001": ("电压正常", "INFO"),
    "ALM-0x02000003": ("电压过高", "MAJOR"),
    "ALM-0x02000005": ("电压过低", "MAJOR"),
    "ALM-0x02000007": ("电压浪涌", "MAJOR"),
    "ALM-0x02000009": ("电压跌落", "MAJOR"),

    # ===== Processor / CPU (0x07) =====
    "ALM-0x07000001": ("CPU正常", "INFO"),
    "ALM-0x07000003": ("CPU故障", "CRITICAL"),
    "ALM-0x07000005": ("CPU温度过高", "MAJOR"),
    "ALM-0x07000007": ("CPU温度恢复", "INFO"),
    "ALM-0x07000009": ("CPU热关机", "CRITICAL"),
    "ALM-0x0700000B": ("CPU热关机恢复", "INFO"),
    "ALM-0x0700000D": ("CPU微码更新失败", "MAJOR"),
    "ALM-0x0700000F": ("CPU配置错误", "MAJOR"),
    "ALM-0x07000011": ("CPU QPI链路故障", "MAJOR"),
    "ALM-0x07000013": ("CPU QPI链路恢复", "INFO"),
    "ALM-0x07000015": ("CPU IMDB 错误", "MINOR"),
    "ALM-0x07000017": ("CPU MCE 错误", "CRITICAL"),
    "ALM-0x07000019": ("CPU MCA 错误", "MINOR"),
    "ALM-0x0700001B": ("CPU温度过高即将触发降频", "MAJOR"),

    # ===== Disk (0x40) =====
    "ALM-0x40000001": ("硬盘正常", "INFO"),
    "ALM-0x40000003": ("硬盘故障", "CRITICAL"),
    "ALM-0x40000005": ("硬盘不在位", "MINOR"),
    "ALM-0x40000007": ("硬盘存在", "INFO"),
    "ALM-0x40000009": ("硬盘Predictive Failure", "MINOR"),
    "ALM-0x4000000B": ("硬盘温度过高", "MAJOR"),
    "ALM-0x4000000D": ("硬盘温度恢复", "INFO"),
    "ALM-0x4000000F": ("硬盘写入量超限", "MINOR"),
    "ALM-0x40000011": ("硬盘读取量超限", "MINOR"),
    "ALM-0x40000013": ("硬盘重建开始", "MINOR"),
    "ALM-0x40000015": ("硬盘重建完成", "INFO"),
    "ALM-0x40000017": ("硬盘重建失败", "CRITICAL"),
    "ALM-0x40000019": ("硬盘坏道", "MINOR"),
    "ALM-0x4000001B": ("硬盘SMART信息异常", "MINOR"),
    "ALM-0x4000001D": ("硬盘一致性问题", "MINOR"),
    "ALM-0x4000001F": ("硬盘ESD保护触发", "MINOR"),
    "ALM-0x40000021": ("硬盘加电失败", "MAJOR"),
    "ALM-0x40000023": ("硬盘格式化完成", "INFO"),
    "ALM-0x40000025": ("硬盘格式化失败", "MAJOR"),
    "ALM-0x40000027": ("硬盘拔出", "MINOR"),
    "ALM-0x40000029": ("硬盘插入", "INFO"),
    "ALM-0x4000002B": ("硬盘初始化失败", "MAJOR"),
    "ALM-0x4000002D": ("硬盘BBU故障", "MAJOR"),
    "ALM-0x4000002F": ("硬盘BBU正常", "INFO"),
    "ALM-0x40000031": ("硬盘BBU电量低", "MINOR"),
    "ALM-0x40000033": ("硬盘BBU充电中", "INFO"),
    "ALM-0x40000035": ("硬盘BBU放电中", "INFO"),
    "ALM-0x40000037": ("硬盘BBU测试中", "INFO"),
    "ALM-0x40000039": ("硬盘BBU测试完成", "INFO"),
    "ALM-0x4000003B": ("Storage Device Predictive Failure", "MINOR"),

    # ===== PCIe Switch (0x3E) =====
    "ALM-0x3E000001": ("PCIe Switch正常", "INFO"),
    "ALM-0x3E000003": ("PCIe Switch故障", "CRITICAL"),
    "ALM-0x3E000005": ("PCIe Switch端口故障", "MAJOR"),
    "ALM-0x3E000007": ("PCIe Switch端口正常", "INFO"),
    "ALM-0x3E000009": ("PCIe Switch温度过高", "MAJOR"),
    "ALM-0x3E00000B": ("PCIe Switch温度恢复", "INFO"),
    "ALM-0x3E00000D": ("PCIe Switch端口Training失败", "MAJOR"),
    "ALM-0x3E00000F": ("PCIe Switch端口Training成功", "INFO"),
    "ALM-0x3E000011": ("PCIe Switch带宽降级", "MINOR"),
    "ALM-0x3E000013": ("PCIe Switch带宽恢复", "INFO"),
    "ALM-0x3E000015": ("PCIe Switch固件更新失败", "MAJOR"),
    "ALM-0x3E000017": ("PCIe Switch温度读取失败", "MINOR"),
    "ALM-0x3E000019": ("PCIe Switch访问超时", "MAJOR"),
    "ALM-0x3E00001B": ("PCIe Switch访问恢复", "INFO"),
    "ALM-0x3E00001D": ("PCIe Switch控制器故障", "CRITICAL"),
    "ALM-0x3E00001F": ("PCIe Switch控制器正常", "INFO"),

    # ===== Battery (0x1C) =====
    "ALM-0x1C000001": ("电池正常", "INFO"),
    "ALM-0x1C000003": ("电池故障", "MAJOR"),
    "ALM-0x1C000005": ("电池电量低", "MINOR"),
    "ALM-0x1C000007": ("电池充电中", "INFO"),
    "ALM-0x1C000009": ("电池放电中", "INFO"),
    "ALM-0x1C00000B": ("电池温度过高", "MAJOR"),
    "ALM-0x1C00000D": ("电池温度恢复正常", "INFO"),
    "ALM-0x1C00000F": ("电池电压过低", "MINOR"),
    "ALM-0x1C000011": ("电池电压恢复正常", "INFO"),
    "ALM-0x1C000013": ("电池不存在", "MINOR"),
    "ALM-0x1C000015": ("电池存在", "INFO"),
    "ALM-0x1C000017": ("电池校准失败", "MINOR"),
    "ALM-0x1C000019": ("电池通信失败", "MAJOR"),
    "ALM-0x1C00001B": ("电池通信恢复", "INFO"),

    # ===== Boot / OS (0x20, 0x23) =====
    "ALM-0x20000001": ("系统启动正常", "INFO"),
    "ALM-0x20000003": ("系统启动失败", "CRITICAL"),
    "ALM-0x20000005": ("系统启动超时", "MAJOR"),
    "ALM-0x20000007": ("系统启动中止", "MINOR"),
    "ALM-0x23000001": ("操作系统启动成功", "INFO"),
    "ALM-0x23000003": ("操作系统启动失败", "CRITICAL"),
    "ALM-0x23000005": ("操作系统运行异常", "MAJOR"),
    "ALM-0x23000007": ("操作系统关闭", "INFO"),
    "ALM-0x23000009": ("操作系统蓝屏", "CRITICAL"),

    # ===== Watchdog (0x27) =====
    "ALM-0x27000001": ("看门狗重启系统", "MAJOR"),
    "ALM-0x27000003": ("看门狗定时器启动", "INFO"),
    "ALM-0x27000005": ("看门狗定时器停止", "INFO"),
    "ALM-0x27000007": ("看门狗超时", "MAJOR"),

    # ===== Health Event (0x68) =====
    "ALM-0x68000001": ("系统健康状态正常", "INFO"),
    "ALM-0x68000003": ("系统健康状态异常", "MAJOR"),
    "ALM-0x68000005": ("系统健康状态恢复", "INFO"),
    "ALM-0x68000007": ("系统健康状态严重", "CRITICAL"),

    # ===== Generic / Fallback =====
    "ALM-0x00000001": ("系统正常", "INFO"),
    "ALM-0x00000003": ("CPU温度过高即将触发降频", "MAJOR"),
    "ALM-0x00000005": ("内存错误", "MINOR"),
    "ALM-0x00000007": ("系统异常", "MAJOR"),
    "ALM-0x00000009": ("系统正常", "INFO"),
    "ALM-0x0000000B": ("电源异常", "CRITICAL"),
    "ALM-0x0000000D": ("风扇异常", "MAJOR"),
    "ALM-0x0000000F": ("温度异常", "MAJOR"),
}


# ---------------------------------------------------------------------------
# Regex: matches "ALM-0xXXXXXXXX" anywhere in a string
# ---------------------------------------------------------------------------

ALM_RE = re.compile(r"ALM-0x([0-9A-Fa-f]{8})")


# ---------------------------------------------------------------------------
# AlarmCodeInfo dataclass
# ---------------------------------------------------------------------------

@dataclass
class AlarmCodeInfo:
    code: str            # full alarm code, e.g. "ALM-0x2C000007"
    subsystem: str       # e.g. "System", "Memory"
    alarm_id: str        # e.g. "0x2C000007"
    description: str     # e.g. "系统异常下电"
    severity: str        # "CRITICAL" | "MAJOR" | "MINOR" | "INFO"
    severity_zh: str      # "紧急" | "严重" | "轻微" | "提示"

    def to_level(self) -> str:
        """Convert severity to log level."""
        if self.severity in ("CRITICAL", "MAJOR"):
            return "ERROR"
        elif self.severity == "MINOR":
            return "WARNING"
        return "INFO"

    def to_rule_id(self) -> str:
        """Generate a rule ID for this alarm."""
        return f"alm_{self.alarm_id.lower()}"


# ---------------------------------------------------------------------------
# Decoding functions
# ---------------------------------------------------------------------------

def decode_alm(code: str) -> Optional[AlarmCodeInfo]:
    """Decode a Huawei alarm code string into AlarmCodeInfo.

    Handles codes with or without the "ALM-" prefix, with 0x prefix,
    and with or without leading zeros.
    """
    code = code.strip().upper()
    if code.startswith("ALM-"):
        code = code[4:]
    if code.startswith("0X"):
        code = code[2:]

    if len(code) > 8:
        return None
    try:
        padded = code.zfill(8)
        int(padded, 16)
    except ValueError:
        return None

    full_code = f"ALM-0x{padded}"
    if full_code in ALARM_DB:
        description, severity = ALARM_DB[full_code]
        subsystem_nn = padded[0:2]
        subsystem_name = SUBSYSTEM.get(subsystem_nn, f"Unknown(0x{subsystem_nn})")
        severity_zh_map = {"CRITICAL": "紧急", "MAJOR": "严重", "MINOR": "轻微", "INFO": "提示"}
        return AlarmCodeInfo(
            code=full_code,
            subsystem=subsystem_name,
            alarm_id=f"0x{padded}",
            description=description,
            severity=severity,
            severity_zh=severity_zh_map.get(severity, severity),
        )

    # Try to decode by subsystem even if not in DB
    subsystem_nn = padded[0:2]
    subsystem_name = SUBSYSTEM.get(subsystem_nn, f"Unknown(0x{subsystem_nn})")
    last_nibble = int(padded[-1], 16)
    sev_nn = SEVERITY_NN.get(last_nibble, ("提示", "INFO"))
    severity_zh_map = {"CRITICAL": "紧急", "MAJOR": "严重", "MINOR": "轻微", "INFO": "提示"}
    if isinstance(sev_nn, tuple):
        sev_zh, sev = sev_nn
    else:
        sev_zh, sev = "提示", "INFO"
    return AlarmCodeInfo(
        code=full_code,
        subsystem=subsystem_name,
        alarm_id=f"0x{padded}",
        description=f"未知告警({full_code})",
        severity=sev,
        severity_zh=sev_zh,
    )


def extract_alm_codes(text: str) -> list[AlarmCodeInfo]:
    """Find all Huawei ALM alarm codes in text, return decoded info list."""
    results = []
    seen = set()
    for m in ALM_RE.finditer(text):
        raw = m.group(0)
        if raw in seen:
            continue
        info = decode_alm(raw)
        if info:
            results.append(info)
            seen.add(raw)
    return results


def is_alm_code(text: str) -> bool:
    """Return True if text contains a Huawei alarm code."""
    return bool(ALM_RE.search(text))
