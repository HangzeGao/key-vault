# TODO

### ECB/GCM suite isolation

- [x] 支持 `AES_256_ECB` 与 `SM4_ECB`。
  - `AES_256_GCM`、`SM4_GCM`、`AES_256_ECB`、`SM4_ECB` 均为独立 suite；Key 创建、受控导入、Envelope、前端选择器与批量导入示例已覆盖。
  - 解密时 Envelope suite 必须与 Key suite 完全一致，GCM Key 不能用于 ECB，ECB Key 不能用于 GCM。
  - ECB Envelope 使用空 nonce、空 tag 和 PKCS#7 padding；wire/JSON 不携带 `aad_hash`。ECB 忽略 caller AAD，仅用于兼容性场景，不提供 GCM 等价的完整性或 AAD 认证能力。

更新时间：2026-07-10

当前工程基线的代码、测试、前端、SDK 和设计清理项已全部完成。本文保留完成记录与环境验收说明；“暂不做”是明确的架构决策，不计入未完成任务。

## 完成状态

### P0 · 安全边界与生产化

- [x] 完成 Ops Plane 高危动作统一治理。
  - `repair-aad-digest`、resolver refresh、lifecycle retry、outbox replay 统一要求 `reason`、`ticket_id`、`Idempotency-Key`。
  - 统一记录 target/current state/impact/rollback/expected result preflight，审计链形成 `requested -> succeeded|failed|aborted` 配对。
  - 审计或幂等预留不可用时 fail-closed；响应只返回 ticket、状态、preflight 和脱敏摘要。
- [x] 实现独立 `ops:breakglass` 流程。
  - 独立 URL 前缀与 scope；额外要求 `impact_scope` 和 `operator_confirmation`。
  - 白名单只覆盖既有修复动作，不存在任意 SQL、shell、脚本、备份/密钥导出和直接 purge。
  - 已覆盖缺 reason/ticket/幂等键、缺强确认、审计失败及 plane/scope 越权负向测试。
- [x] 实现进程内原生 TPM provider。
  - `native` / `tss` / `esapi` 使用 go-tpm，不 shell out、不依赖 PATH、不写 CRK 明文临时文件；错误 transport 启动失败。
  - 支持 TPM sealed object 持久 envelope、重启恢复、上下文错误和 envelope 损坏拒绝；vTPM 测试在支持 CGO 的测试环境运行。
  - `software`、`swtpm`、`tpm2-tools` 保留为工程 fallback，生产配置显式拒绝。
- [x] 将 CRK 上下文绑定下沉到 TPM 强制边界。
  - 配置 PCR 集通过 `PolicyPCR` 约束；`cluster_id`、`node_id`、`plane_role`、`baseline_digest`、`policy_digest` 的 canonical context 参与 TPM object authorization。
  - 设计文档明确 `crk_aad_digest` 仅为应用层完整性校验。
- [x] 补齐数据面 AAD 合约与租户策略。
  - 单条/批量统一处理未传、空、非法 base64、非空与错误 AAD；错误使用稳定码且不泄露 AEAD/Envelope 内部细节。
  - tenant envelope config 增加 `aad_required`，Encrypt/Decrypt/Batch 和前端保持一致。
- [x] 落地容量保护与限流。
  - 使用 `rate_window`、`rate_sigma_threshold`，覆盖 hot key、crypto、batch、audit、lifecycle/outbox 与 Ops 变更请求。
  - 保留 64 KiB body、100 条 batch 上限，响应增加逐项结果、成功/失败汇总和 failure ratio；限流返回 429、`Retry-After` 与剩余额度。
- [x] 加强生产部署安全门禁。
  - `environment: production` 强制 PostgreSQL、native TPM、physical plane isolation；production fingerprint 不明确时拒绝启动。
  - 审计递归脱敏覆盖 token、authorization、plaintext、DEK/CRK、wrapped material、ciphertext/envelope，同时避免误伤 `envelope_format` 等安全元数据。
  - PostgreSQL 集成测试覆盖迁移、连接、乐观并发/事务冲突；生产安全、备份恢复和敏感信息扫描流程记录在 `baseline/docs/PRODUCTION_SECURITY.md`。
- [x] 修正严格 JSON 解码。
  - 拒绝未知字段、尾随 JSON 和任意深度重复字段；覆盖嵌套对象、batch entries 与 profile map。

### P1 · 契约、交互与自动化

- [x] 统一 API 路径和请求契约。
  - `src/lib/apiPaths.ts` 集中管理 BFF path、动态 ID 编码和 query builder；文档统一采用 `/retry`、`/replay`。
- [x] 增加前端契约、页面和截图测试。
  - Vitest 覆盖 Dashboard、Keys、Crypto、BatchCrypto、Audit、Lifecycle、EnvelopeConfig、Policy 的 empty/success，以及权限错误和大列表/长 ID。
  - Playwright 使用 Edge 覆盖 desktop 与 390px narrow 登录布局、水平溢出和截图基线。
- [x] 收敛前端样式与业务组件。
  - 通用 `page-header`、`page-section`、`table-scroll`、`record-card`、toolbar/filter/pagination/profile editor 类已落地。
  - Dashboard 的健康、指标、状态和可操作事项使用共享 Ops widgets；贡献约定禁止复制大段 inline layout。
- [x] 优化 BatchCrypto。
  - 支持清空、JSON/CSV 文件导入、批量粘贴、失败过滤/重试、成功结果批量复制和 UTF-8/base64/hex AAD。
- [x] 优化 EnvelopeConfig。
  - 支持 profile 表单、field mapping 行编辑、adapter/path 校验、JSON 预检、保存前 diff、乐观版本冲突重拉且保留编辑内容，以及 `aad_required`。
- [x] 完善 Audit 和 Lifecycle 大列表。
  - Audit 支持 action/result/actor/target/time range 过滤；audit/jobs/outbox 支持 cursor 分页与服务端 limit 上限。
  - outbox payload 限高，只显示并复制递归脱敏摘要。
- [x] 完成 SDK AAD canonical helper。
  - `sdk/aad` 提供 RFC 8785/JCS JSON、deterministic protobuf bytes、raw bytes 和 HTTP header allowlist canonical helper。
  - `testdata/vectors.json` 作为跨语言固定测试向量。
- [x] 对齐设计文档与实现。
  - FR 编号、Ops route、TPM/NRWK/CRK/DEK/Data 层次均已统一。
  - `ops-enhancement-design.md` 已并入《工程基线详细设计》§4.1，不再保留重复设计文档。
- [x] 增加 backend integration / E2E 测试。
  - 覆盖 APIAccess plane/scope、HMAC replay、Ops 审计 fail-closed、break-glass 负向门禁、lifecycle/outbox 幂等、Key 到期/销毁状态机、PostgreSQL 迁移与并发版本控制。

### P2 · 可维护性与开发体验

- [x] 为 `crypto/envelope`、`crypto/aad`、`resolver/keyresolver`、`tpm/provider`、`application/crypto`、`api/middleware` 补充 README。
- [x] 补充 Windows `npm.cmd`、受限沙箱 Vite/esbuild、工作区 `GOCACHE` 与缓存清理说明。
- [x] 增加前端设计系统文档。
- [x] 完善 Dashboard 信息分层。
  - 可操作事项直达 lifecycle/CRK/audit；展示最近高风险审计和 lifecycle 活动；页面明确 tenant key inventory 与全局 Ops 状态的维度差异。
  - Ops Dashboard 通过 `ops/db/status` 可视化全局数据库聚合：Key 状态、suite 分布、purpose 统计和 repository table row counts；不绕过平面隔离返回 Key ID、标签或密钥材料。
  - 对称 AEAD 基线将 Key purpose 收敛为 `encrypt_decrypt`；前端、服务层、加解密路径与数据库约束均拒绝不受支持的 `signing` 等用途。
  - PostgreSQL 使用事务化版本迁移账本与 advisory lock；历史 purpose 在约束前归一化，避免每次启动重复执行 DDL。
  - 前端默认提供 Daily workflow 简单模式；Policy、Envelope、Batch、Audit、Lifecycle 等控制项按需切换到 Advanced controls。
  - 启动日志输出非敏感部署体检：运行环境、存储持久性、TPM provider 和 plane 隔离级别。
  - 审计链哈希以首尾 fingerprint 紧凑展示，并支持一键复制完整 chain head/event hash；已脱敏 actor/target fingerprint 不再追加误导性的省略号。
  - Dashboard 移除与顶部状态卡重复的 Storage posture；将 Cluster 与 CRK 拆为与 Health/Database/Keys 同风格的状态卡，突出 epoch、节点、CRK 版本、状态与 AAD digest。
  - 总体设计架构图按“系统上下文 → 平面与权限 → 内部执行与可信边界”由浅入深展开；英文三层图后提供语义等价的中文三层图。
  - 新增管理面批量受控导入 Key（最多 100 条、逐条校验与结果、不回显 DEK）；批量解密与批量加密一样支持 JSON/CSV 粘贴和文件导入。
  - 提供独立 JSON/CSV 示例文件：批量 Key 导入、批量加密与批量解密各一组，并在示例 README 说明占位材料、AAD 编码与替换要求；批量解密操作区与加密对齐，支持 Clear。
  - Dashboard 全部 Health 卡均可展开查看脱敏运行态：TPM provider/PCR、Resolver CRK 缓存、数据库持久性与连接、Worker 参数与失败数、审计链校验、策略版本与受信任签名键数；不返回设备标识、DSN、密钥材料或完整审计载荷。
  - Dashboard 定义 Health 的 OK/WARN/DEGRADED 语义；TPM WARN 明确说明 `tpm2` 等兼容 provider 已初始化但低于生产原生 TPM 基线，并给出 native/tss/esapi 的升级方向。
  - Dashboard 以 Data Atlas 作为唯一的密钥库存明细（总量、状态、套件、用途）；移除重复的 Key Inventory 区块。Repository footprint 显示全部 repository table row counts（包括零行的 `attestation_baselines` 与 `attestation_challenges`）；宽屏双列、窄屏单列。
  - PostgreSQL `pg_class.reltuples=-1`（尚未 ANALYZE 的统计未知）在 Ops table sizes 中归一为 `0`，前端不再将其显示为 `-`。
- [x] 收敛 Envelope inspect/convert 协议边界。
  - 前端不再实现 Envelope 协议解析或重编码；只调用服务端 inspect/convert。服务端统一执行 parser/profile 选择、租户格式白名单、严格 JSON 数字边界和审计，示例文件不再硬编码策略 ID。
- [x] 完成 DESTROYED Key 归档与历史销毁任务自愈。
  - `DESTROYED` Key 支持归档 tombstone，默认 Key 库存隐藏归档项，显式 `include_archived=true` 可查看；不物理删除 Key ID、最小元数据或审计证据。
  - 启动时为缺少 `PENDING/RUNNING destroy_due` job 的历史 `DESTROY_PENDING` Key 补建销毁任务，补建时间按 `updated_at + 24h`，失败 job 仍通过 Ops retry 处理。
- [x] 增加 route-level ErrorBoundary，组件渲染异常不再导致整站空白。

## 验证记录

- `go test ./...`
- `npm.cmd test`：12 tests passed
- `npm.cmd run build`：TypeScript + Vite production build passed
- `npm.cmd run test:e2e`：desktop/narrow 2 tests passed
- TPM simulator 测试在当前 `CGO_ENABLED=0` 环境自动跳过；CI/部署验收须在启用 CGO 的 vTPM 或真实 TPM runner 上执行。
- PostgreSQL integration test 通过 `KVLT_TEST_POSTGRES_DSN` 在隔离数据库运行；本机无 Docker daemon 时自动跳过。

## 明确暂不做

- 不删除 `tpm2-tools` fallback；它仅用于 PoC、受控验证和本地联调，生产必须使用 native provider。
- 不把 `/ui/api/v1` 直接重命名为 `/api/v1`；未来公共 API 单独设计版本化契约。
- 不由服务端 canonicalize 数据面业务 AAD；服务端只消费 opaque `aad_b64` bytes，canonicalization 由调用方或 SDK 完成。
