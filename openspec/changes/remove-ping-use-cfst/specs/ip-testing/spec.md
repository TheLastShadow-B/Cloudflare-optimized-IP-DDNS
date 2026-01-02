## ADDED Requirements

### Requirement: IP 测试统一使用 cfst
系统 SHALL 使用 CloudflareSpeedTest (cfst) 工具对所有候选 IP 进行统一测试，获取延迟、丢包率和下载速度数据。

#### Scenario: cfst 测试所有 IP
- **WHEN** 系统完成 IP 解析后
- **THEN** 使用 cfst 对所有解析到的 IP 进行测试
- **AND** cfst 使用 `CFST_PING_COUNT` 配置的次数进行 ping 测试（默认 10 次）
- **AND** 测试结果包含每个 IP 的延迟、丢包率和下载速度

### Requirement: 最佳 IP 选择策略
系统 SHALL 按以下策略选择最佳 IP：先过滤丢包率为 0 的 IP，再按下载速度降序排序，选择速度最快的 IP。

#### Scenario: 选择丢包率为 0 且速度最快的 IP
- **WHEN** cfst 测试完成后
- **THEN** 系统过滤出丢包率为 0 的 IP
- **AND** 按下载速度降序排序
- **AND** 选择排名第一的 IP 作为最佳 IP

#### Scenario: 所有 IP 都有丢包
- **WHEN** 没有丢包率为 0 的 IP
- **THEN** 系统输出警告日志
- **AND** 从所有 IP 中选择丢包率最低且速度最快的 IP

### Requirement: cfst Ping 次数配置
系统 SHALL 支持通过 `CFST_PING_COUNT` 环境变量配置 cfst 的 ping 测试次数，以确保丢包率数据准确。

#### Scenario: 使用默认 ping 次数
- **WHEN** 未配置 `CFST_PING_COUNT`
- **THEN** 使用默认值 10 次

#### Scenario: 使用自定义 ping 次数
- **WHEN** 配置 `CFST_PING_COUNT=20`
- **THEN** cfst 使用 20 次 ping 测试

## REMOVED Requirements

### Requirement: Ping 测试
**Reason**: cfst 已提供延迟和丢包率数据，独立的 ping 测试冗余
**Migration**: 使用 cfst 测试替代，通过 `CFST_PING_COUNT` 配置 ping 次数

### Requirement: SKIP_PING 配置
**Reason**: 不再有独立的 ping 测试阶段
**Migration**: 直接删除此配置项

### Requirement: PING_COUNT 和 PING_WORKERS 配置
**Reason**: 不再使用独立的 ping 测试
**Migration**: 使用 `CFST_PING_COUNT` 替代 ping 次数配置
