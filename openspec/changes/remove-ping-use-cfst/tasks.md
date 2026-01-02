# Tasks

## 1. 更新配置
- [x] 1.1 从 `Config` 类移除 `ping_count`、`ping_workers`、`skip_ping` 字段
- [x] 1.2 新增 `cfst_ping_count` 字段（默认值 10）
- [x] 1.3 更新 `.env` 模板：移除旧配置项，新增 `CFST_PING_COUNT`
- [x] 1.4 更新 `load_config()` 函数解析新配置

## 2. 移除 Ping 测试代码
- [x] 2.1 删除 `PingResult` 数据类
- [x] 2.2 删除 `ping_ip()` 函数
- [x] 2.3 删除 `parse_unix_ping()` 函数
- [x] 2.4 删除 `parse_windows_ping()` 函数
- [x] 2.5 删除 `test_all_ips()` 函数
- [x] 2.6 删除 `select_best_ip()` 函数

## 3. 更新 cfst 测试逻辑
- [x] 3.1 修改 `run_speed_test()` 支持 `-t` 参数设置 ping 次数
- [x] 3.2 更新 `SpeedTestResult` 添加 `packet_loss` 字段
- [x] 3.3 解析 cfst 结果时提取丢包率数据

## 4. 更新主流程
- [x] 4.1 修改 `main()` 函数：移除 ping 测试分支
- [x] 4.2 实现新的 IP 选择逻辑：过滤丢包率为 0 → 按速度排序
- [x] 4.3 更新日志输出，反映新的测试流程

## 5. 验证
- [x] 5.1 Python 语法检查通过
- [ ] 5.2 手动测试：运行脚本验证完整流程（需用户执行）
