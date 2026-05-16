# Log file priority patterns — single source of truth for both
# archive scanning (main.py / log_scanner.py) and ibmc_dump.py.
#
# Ordered by diagnostic value (highest first).
# Used by: log_scanner._find_top_log_files, ibmc_dump._scan_dump_dir

LOG_PRIORITY_PATTERNS: list[str] = [
    # Application debug / operational logs (highest debugging value)
    "app_debug_log_all",
    "ipmi_mass_operate_log",
    "ipmi_debug_log",
    "operate_log",
    "security_log",
    "strategy_log",
    "mass_operate_log",
    "remote_log",
    # Module dfl structured diagnostic output
    "BMC_dfl",
    "sensor_alarm_dfl",
    "PowerMgnt_dfl",
    "UPGRADE_dfl",
    "BIOS_dfl",
    "card_manage_dfl",
    "CpuMem_dfl",
    "cooling_app_dfl",
    "Snmp_dfl",
    "ddns_dfl",
    "diagnose_dfl",
    "discovery_dfl",
    "agentless_dfl",
    "kvm_vmm_dfl",
    "ipmi_app_dfl",
    "fileManage_dfl",
    "StorageMgnt_dfl",
    "rimm_dfl",
    "redfish_dfl",
    "Dft_dfl",
    "net_nat_dfl",
    "PcieSwitch_dfl",
    "MaintDebug_dfl",
    # IPMI / SEL (high diagnostic value)
    "ipmi_sel",
    "IPMI_SEL",
    "ipmi_seld",
    "BMC_dump",
    "core_dump",
    # High-availability / web / XML exports
    "ha_log",
    "web_log",
    "export.xml",
    # CPLD / FPGA version info
    "cpld_info",
    "fpga_info",
    # Additional dfl modules
    "webapp_dfl",
    "restful_dfl",
    # Sensor / hardware info
    "sensor_data",
    "psu_status",
    "raid_status",
    "disk_info",
    # Linux / systemd
    "syslog",
    "journal",
    # Mass / remote operate
    "ipmi_mass",
    "rmt_mnt_log",
    # Module info
    "module_info",
    # Sensor / hardware info
    "sensor_info",
    "fan_info",
    "cpu_info",
    "mem_info",
    "net_info",
    "psu_info",
    "fruinfo",
    "nandflash_info",
    "time_zone",
    "ntp_info",
    "bios_info",
    "card_info",
    # Linux / kernel
    "linux_kernel_log",
    "dmesg",
    "app_debug",
    # Maintenance
    "maintenance_log",
    "md_so_maintenance_log",
    "md_so_operate_log",
    "md_so_strategy_log",
    # DFM debug
    "dfm_debug_log",
    "dfm.log",
    "raid",
    "lsi",
]
