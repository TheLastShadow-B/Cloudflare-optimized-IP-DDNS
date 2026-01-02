# Change: 移除 Ping 测试，统一使用 cfst 进行延迟和速度测试

## Why
当前流程分两阶段测试：先用 ping 测试所有 IP 的延迟和丢包率，再用 cfst 对筛选后的 IP 进行速度测试。这导致：
1. 测试时间长（两轮测试）
2. 代码复杂（需维护两套测试逻辑和结果解析）
3. cfst 本身已提供延迟和丢包率数据，ping 测试冗余

## What Changes
- **移除** ping 测试相关函数（`ping_ip`, `test_all_ips`, `parse_unix_ping`, `parse_windows_ping`, `select_best_ip`）
- **移除** `PingResult` 数据类
- **移除** `.env` 中的 `PING_COUNT` 和 `PING_WORKERS` 配置项
- **修改** cfst 测试逻辑：直接测试所有解析到的 IP
- **新增** cfst ping 次数配置项 `CFST_PING_COUNT`（默认 10 次，确保丢包率准确）
- **修改** 最佳 IP 选择逻辑：先过滤丢包率为 0 的 IP，再按下载速度降序排序
- **移除** `SKIP_PING` 配置项（不再需要）

## Impact
- Affected specs: ip-testing (新建)
- Affected code: `he_dns_updater.py`
- **BREAKING**: 移除 `PING_COUNT`、`PING_WORKERS`、`SKIP_PING` 配置项
