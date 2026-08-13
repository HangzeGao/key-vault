# Grilling 决策验收矩阵

本文是“降低复杂度”决策完成度的逐项证据，不以口头设计或单独单元测试代替交付。

| 已接受决策 | 实现证据 | 验证证据 | 状态 |
|---|---|---|---|
| TC 与高速上注/数传下行彻底分离 | `internal/protocol/ccsds` 与 `internal/downlink`；独立 API/scope/状态 | Go 全量测试；TC 与 downlink 独立 E2E | 已实现并验收 |
| 高速上注不加密，DEK 包自身由 KEK 保护 | `internal/downlink/package.go` 固定 SM4-GCM 包 | 包回环及字段/密文/Tag 篡改拒绝测试 | 已实现 |
| 每星专用 8 组 KEK | Mission Profile 固定 128 字节 KEKSet；slot 0..7 | profile、TPM seal、slot 边界测试 | 已实现 |
| 1024 个全量 DEK，固定位置编号 | `DEKCount=1024`、每项 16 字节 | serial 0/1023、越界和 HTTP E2E | 已实现 |
| 不使用下行 KDF | 下行直接取位置 DEK；无 KDF 调用 | 静态搜索及 downlink 测试 | 已实现 |
| 上注 nonce 与硬件下行 nonce 均显式传输，不确定性推导 | 两种线格式均固定 12 字节 nonce | 格式、长度、认证失败测试 | 已实现 |
| 星载硬件实现不在本项目范围 | 仅提供格式模拟器，不实现硬件控制 | `examples/downlink-hardware-simulator` | 已实现 |
| 包头为 `slot|generation` 并纳入 AAD | `Package.header()` | 头部篡改拒绝测试 | 已实现 |
| 批次只能严格递增，不允许跳代或回绕 | SQLite CAS 与 uint32 耗尽拒绝 | 并发/冲突/耗尽测试 | 已实现 |
| 重传必须复用完全相同包 | 数据库保存 Current 包；`export-current-dek-batch` | 摘要校验与导出测试 | 已实现 |
| Current 未被真实下行观测前禁止生成下一批 | `current_observed` 门禁 | Current 认证成功提交、失败不提交测试 | 已实现 |
| 只保留 Current/Previous 两批；Current 优先，Previous 最多一次 | 运行时双批缓存 | 两批切换、重启和错误 Tag 测试 | 已实现 |
| 不增加 downlink replay window | schema 与 service 无 downlink replay 状态 | schema/静态搜索 | 已实现 |
| AOS 仅保留未来适配口，不建立 SA/生命周期 | 删除 AOS SA、API 和 replay 表；`RAW` 合同 | 旧 AOS 路由拒绝、schema 测试 | 已实现 |
| KEKSet 直接 TPM seal；删除 CRK/SWK | `TPMSealer` 与直接 sealed protocol roots | TPM context、解封失败测试 | 已实现 |
| 离线 CLI 是唯一密钥批次写入口 | `cmd/downlink-keyctl`；前端无写按钮 | CLI 编译、API 路由矩阵 | 已实现 |
| 单星 singleton 下行状态 | `downlink_key_state(singleton=1)` | 重复 provision/冲突测试 | 已实现 |
| 运维页只读展示真实状态 | Ops status 返回 slot/generation/observed/previous | API 与前端页面测试 | 已实现 |
| 用户手册与可运行 example | `DOWNLINK_KEY_USER_MANUAL.md` 与模拟器 | 示例编译、真实 SQLite+TPM+HTTP E2E | 已实现 |
| 删除旧通用导入/批量密码示例 | `examples` 只保留当前两类合同 | 文件清单审查 | 已实现 |
| 所有强制覆盖率、C、ARMv7 与发布门禁通过 | `scripts/coverage_gate.sh`、`release_gate.sh` | C 95.41%；地面组合 95.10%；下行 96.50%；ARMv7 与 256 组差分通过 | 已实现并验收 |
| 聚焦提交并按第 5 个领先 commit 推送 | AGENTS 工作流 | staged diff、commit、ahead count | 纳入本次交付流程 |

## 发布门禁证据

完整 `release-gate` 已在配置的 Linux/ARMv7 集成服务器独立候选目录执行并生成 `build/release/release-evidence.json`。验收结果：

- 前端 12 项测试和生产构建通过；
- 全量 Go、TC API 到星载和下行批次到 HTTP 明文 E2E 通过；
- Go/C software/ARMv7-NEON 256 组差分通过；
- 星载 C 行覆盖率 95.41%；
- 地面 TC/状态/密码组合语句覆盖率 95.10%；
- 地面下行 Go 语句覆盖率 96.50%。
